rule PEiD_01746_PolyCrypt_PE___2_1_4b_2_1_5____JLab_Software_Creations__h_oep__ {
  meta:
    description = "[PolyCrypt PE - 2.1.4b/2.1.5 -> JLab Software Creations (h-oep)]"
    ep_only     = "false"

  strings:
    $a = { 91 8B F4 AD FE C9 80 34 08 ?? E2 FA C3 60 E8 ED FF FF FF EB }

  condition:
    $a
}