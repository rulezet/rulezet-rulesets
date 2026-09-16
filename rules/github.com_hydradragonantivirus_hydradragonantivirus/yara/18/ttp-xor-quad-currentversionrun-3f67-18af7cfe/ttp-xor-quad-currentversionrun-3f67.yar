rule TTP_XOR_QUAD_CurrentVersionRun_3f67 {
  strings:
    $key_3f67 = { 6c 08 [2] 48 06 [2] 63 2a [2] 4d 08 [2] 59 13 [2] 56 09 [2] 48 14 [2] 4a 15 [2] 51 13 [2] 4d 14 [2] 51 3b }

  condition:
    any of them
}