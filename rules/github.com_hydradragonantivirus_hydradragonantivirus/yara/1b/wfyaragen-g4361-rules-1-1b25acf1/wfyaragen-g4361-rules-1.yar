rule WFYARAGEN_G4361_rules_1 {
  meta:
    description = "Unique enough typo found in some of the backdoor code"

  strings:
    $re = /usecloack/ nocase

  condition:
    $re
}