rule PEiD_00487_Dr_Web_Virus_Finding_Engine____InSoft_EDV_Systeme_ {
  meta:
    description = "[Dr.Web Virus-Finding Engine -> InSoft EDV-Systeme]"
    ep_only     = "true"

  strings:
    $a = { B8 01 00 00 00 C2 0C 00 8D 80 00 00 00 00 8B D2 8B ?? 24 04 }

  condition:
    $a
}