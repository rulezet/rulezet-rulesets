rule TTP_XOR_QUAD_CurrentVersionRun_6917 {
  strings:
    $key_6917 = { 3a 78 [2] 1e 76 [2] 35 5a [2] 1b 78 [2] 0f 63 [2] 00 79 [2] 1e 64 [2] 1c 65 [2] 07 63 [2] 1b 64 [2] 07 4b }

  condition:
    any of them
}