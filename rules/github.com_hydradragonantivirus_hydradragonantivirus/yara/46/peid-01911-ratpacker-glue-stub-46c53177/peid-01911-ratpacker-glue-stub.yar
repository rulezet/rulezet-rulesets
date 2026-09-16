rule PEiD_01911_RatPacker__Glue__stub_ {
  meta:
    description = "[RatPacker (Glue) stub]"
    ep_only     = "false"

  strings:
    $a = { 40 20 FF ?? ?? ?? ?? ?? ?? ?? ?? BE ?? 60 40 ?? 8D BE ?? B0 FF FF }

  condition:
    $a
}