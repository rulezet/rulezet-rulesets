rule TTP_XOR_QUAD_CurrentVersionRun_0d67 {
  strings:
    $key_0d67 = { 5e 08 [2] 7a 06 [2] 51 2a [2] 7f 08 [2] 6b 13 [2] 64 09 [2] 7a 14 [2] 78 15 [2] 63 13 [2] 7f 14 [2] 63 3b }

  condition:
    any of them
}