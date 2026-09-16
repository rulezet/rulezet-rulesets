rule PEiD_00695_eXPressor_v1_5_0_1__Options____Protection__CGSoftLabs_ {
  meta:
    description = "[eXPressor v1.5.0.1 (Options -> Protection) CGSoftLabs]"
    ep_only     = "true"

  strings:
    $a = { 5E 00 00 80 00 00 00 68 91 5D D4 27 35 C5 5A 4C A5 40 48 C4 08 4E C0 }

  condition:
    $a
}