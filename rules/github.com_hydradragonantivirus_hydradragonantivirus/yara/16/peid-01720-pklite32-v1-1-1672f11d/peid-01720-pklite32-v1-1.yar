rule PEiD_01720_PKLITE32_v1_1_ {
  meta:
    description = "[PKLITE32 v1.1]"
    ep_only     = "false"

  strings:
    $a = { 55 8B EC A1 ?? ?? ?? ?? 85 C0 74 09 B8 01 ?? ?? ?? 5D C2 0C ?? 8B 45 0C 57 56 53 8B 5D 10 }

  condition:
    $a
}