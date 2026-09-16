rule PEiD_00704_FakeNinja_v2_8____Spirit_ {
  meta:
    description = "[FakeNinja v2.8 -> Spirit]"
    ep_only     = "false"

  strings:
    $a = { BA ?? ?? ?? ?? FF E2 64 11 40 00 FF 35 84 11 40 00 E8 40 }

  condition:
    $a
}