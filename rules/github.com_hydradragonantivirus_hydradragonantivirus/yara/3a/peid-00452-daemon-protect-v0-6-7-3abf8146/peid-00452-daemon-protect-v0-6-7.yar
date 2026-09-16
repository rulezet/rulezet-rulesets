rule PEiD_00452_DAEMON_Protect_v0_6_7_ {
  meta:
    description = "[DAEMON Protect v0.6.7]"
    ep_only     = "true"

  strings:
    $a = { 60 60 9C 8C C9 32 C9 E3 0C 52 0F 01 4C 24 FE 5A 83 C2 0C 8B 1A 9D 61 }

  condition:
    $a
}