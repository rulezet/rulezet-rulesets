rule SUSP_Obfuscated_Powershell_b64 {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via b64"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $ = "powershell" base64 base64wide
    $ = "Powershell" base64 base64wide
    $ = "PowerShell" base64 base64wide
    $ = "POWERSHELL" base64 base64wide

  condition:
    any of them
}