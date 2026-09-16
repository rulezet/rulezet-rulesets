rule PEiD_00848_G_X_Protector_1_2____Guru_eXe_ {
  meta:
    description = "[G!X Protector 1.2 -> Guru.eXe]"
    ep_only     = "true"

  strings:
    $a = { 60 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 }

  condition:
    $a
}