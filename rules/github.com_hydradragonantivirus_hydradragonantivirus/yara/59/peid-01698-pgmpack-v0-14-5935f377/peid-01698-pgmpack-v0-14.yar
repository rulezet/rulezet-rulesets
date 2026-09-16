rule PEiD_01698_PGMPACK_v0_14_ {
  meta:
    description = "[PGMPACK v0.14]"
    ep_only     = "true"

  strings:
    $a = { 1E 17 50 B4 30 CD 21 3C 02 73 ?? B4 4C CD 21 FC BE ?? ?? BF ?? ?? E8 ?? ?? E8 ?? ?? BB ?? ?? BA ?? ?? 8A C3 8B F3 }

  condition:
    $a
}