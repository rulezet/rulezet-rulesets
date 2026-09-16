rule PEiD_02449_UPX_v1_03___v1_04_Modified_ {
  meta:
    description = "[UPX v1.03 - v1.04 Modified]"
    ep_only     = "true"

  strings:
    $a = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB 8A 07 ?? EB B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF }

  condition:
    $a
}