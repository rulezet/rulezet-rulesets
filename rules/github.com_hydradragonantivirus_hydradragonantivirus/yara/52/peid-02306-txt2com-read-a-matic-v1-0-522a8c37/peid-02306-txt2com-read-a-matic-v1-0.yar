rule PEiD_02306_TXT2COM__Read_A_Matic_v1_0__ {
  meta:
    description = "[TXT2COM (Read-A-Matic v1.0)]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? 8E D8 8C 06 ?? ?? FA 8E D0 BC ?? ?? FB B4 ?? CD 21 A3 ?? ?? 06 50 B4 34 CD 21 }

  condition:
    $a
}