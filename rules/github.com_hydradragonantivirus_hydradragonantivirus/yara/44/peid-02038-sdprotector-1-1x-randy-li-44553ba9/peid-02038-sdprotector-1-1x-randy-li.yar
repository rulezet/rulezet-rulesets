rule PEiD_02038_SDProtector_1_1x____Randy_Li_ {
  meta:
    description = "[SDProtector 1.1x -> Randy Li]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 }

  condition:
    $a
}