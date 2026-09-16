rule PEiD_01457_Password_Protector__c__MiniSoft_1992_ {
  meta:
    description = "[Password Protector (c) MiniSoft 1992]"
    ep_only     = "true"

  strings:
    $a = { 06 0E 0E 07 1F E8 00 00 5B 83 EB 08 BA 27 01 03 D3 E8 3C 02 BA EA }

  condition:
    $a
}