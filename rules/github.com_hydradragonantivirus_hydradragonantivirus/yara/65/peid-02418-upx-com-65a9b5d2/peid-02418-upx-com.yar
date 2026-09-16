rule PEiD_02418_UPX__com_ {
  meta:
    description = "[UPX [com]"
    ep_only     = "true"

  strings:
    $a = { B9 ?? ?? BE ?? ?? BF C0 FF FD }

  condition:
    $a
}