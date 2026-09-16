rule PEiD_01042_Microsoft_C_Library_1985_ {
  meta:
    description = "[Microsoft C Library 1985]"
    ep_only     = "true"

  strings:
    $a = { BF ?? ?? 8B 36 ?? ?? 2B F7 81 FE ?? ?? 72 ?? BE ?? ?? FA 8E D7 81 C4 ?? ?? FB 73 }

  condition:
    $a
}