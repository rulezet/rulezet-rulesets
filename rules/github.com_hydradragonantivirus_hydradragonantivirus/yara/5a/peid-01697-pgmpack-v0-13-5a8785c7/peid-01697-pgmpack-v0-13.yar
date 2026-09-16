rule PEiD_01697_PGMPACK_v0_13_ {
  meta:
    description = "[PGMPACK v0.13]"
    ep_only     = "true"

  strings:
    $a = { FA 1E 17 50 B4 30 CD 21 3C 02 73 ?? B4 4C CD 21 FC BE ?? ?? BF ?? ?? E8 ?? ?? E8 ?? ?? BB ?? ?? BA ?? ?? 8A C3 8B F3 }

  condition:
    $a
}