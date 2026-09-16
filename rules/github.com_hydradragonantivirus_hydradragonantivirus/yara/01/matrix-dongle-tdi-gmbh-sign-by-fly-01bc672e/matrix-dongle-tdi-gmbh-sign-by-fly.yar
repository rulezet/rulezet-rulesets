import "pe"
rule Matrix_Dongle____TDi_GmbH_____Sign_By_fly {
  strings:
    $a0 = { E8 00 00 00 00 E8 00 00 00 00 59 5A 2B CA 2B D1 E8 1A FF FF FF }

  condition:
    $a0 at pe.entry_point
}