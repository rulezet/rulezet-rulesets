rule PEiD_01910_RatPacker__Glue__stub_ {
  meta:
    description = "[RatPacker (Glue) stub]"
    ep_only     = "true"

  strings:
    $a = { 40 20 FF 00 00 00 00 00 00 00 ?? BE 00 60 40 00 8D BE 00 B0 FF FF }

  condition:
    $a
}