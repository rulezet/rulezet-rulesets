rule PEiD_01662_PeStubOEP_v1_x_ {
  meta:
    description = "[PeStubOEP v1.x]"
    ep_only     = "false"

  strings:
    $a = { 90 33 C9 33 D2 B8 ?? ?? ?? 00 B9 FF }

  condition:
    $a
}