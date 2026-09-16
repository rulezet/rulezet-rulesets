rule TTP_XOR_QUAD_CurrentVersionRun_0b17 {
  strings:
    $key_0b17 = { 58 78 [2] 7c 76 [2] 57 5a [2] 79 78 [2] 6d 63 [2] 62 79 [2] 7c 64 [2] 7e 65 [2] 65 63 [2] 79 64 [2] 65 4b }

  condition:
    any of them
}