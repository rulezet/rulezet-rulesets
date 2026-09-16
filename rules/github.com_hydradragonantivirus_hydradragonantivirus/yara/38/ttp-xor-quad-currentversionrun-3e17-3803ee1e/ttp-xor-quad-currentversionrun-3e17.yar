rule TTP_XOR_QUAD_CurrentVersionRun_3e17 {
  strings:
    $key_3e17 = { 6d 78 [2] 49 76 [2] 62 5a [2] 4c 78 [2] 58 63 [2] 57 79 [2] 49 64 [2] 4b 65 [2] 50 63 [2] 4c 64 [2] 50 4b }

  condition:
    any of them
}