rule SUSP_Obfuscated_Powershell_Casing_Anomaly {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via casing anomalies"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $case1 = "Powershell" nocase ascii wide
    $case2 = "powershell" nocase ascii wide
    $legit1 = "powershell" ascii wide
    $legit2 = "Powershell" ascii wide
  condition:
    none of ($legit*) and any of ($case*)
}