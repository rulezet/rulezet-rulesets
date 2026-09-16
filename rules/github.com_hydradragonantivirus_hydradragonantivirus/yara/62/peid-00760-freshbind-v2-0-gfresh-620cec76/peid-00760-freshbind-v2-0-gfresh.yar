rule PEiD_00760_Freshbind_v2_0____gFresh_ {
  meta:
    description = "[Freshbind v2.0 -> gFresh]"
    ep_only     = "true"

  strings:
    $a = { 64 A1 00 00 00 00 55 89 E5 6A FF 68 1C A0 41 00 }

  condition:
    $a
}