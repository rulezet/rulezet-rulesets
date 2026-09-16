rule TTP_XOR_QUAD_CurrentVersionRun_0667 {
  strings:
    $key_0667 = { 55 08 [2] 71 06 [2] 5a 2a [2] 74 08 [2] 60 13 [2] 6f 09 [2] 71 14 [2] 73 15 [2] 68 13 [2] 74 14 [2] 68 3b }

  condition:
    any of them
}