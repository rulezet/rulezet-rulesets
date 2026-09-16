rule PEiD_02220_The_Guard_Library_ {
  meta:
    description = "[The Guard Library]"
    ep_only     = "true"

  strings:
    $a = { 50 E8 ?? ?? ?? ?? 58 25 ?? F0 FF FF 8B C8 83 C1 60 51 83 C0 40 83 EA 06 52 FF 20 9D C3 }

  condition:
    $a
}