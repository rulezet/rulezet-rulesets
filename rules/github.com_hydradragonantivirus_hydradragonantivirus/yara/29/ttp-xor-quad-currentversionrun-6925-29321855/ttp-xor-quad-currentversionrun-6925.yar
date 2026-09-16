rule TTP_XOR_QUAD_CurrentVersionRun_6925 {
  strings:
    $key_6925 = { 3a 4a [2] 1e 44 [2] 35 68 [2] 1b 4a [2] 0f 51 [2] 00 4b [2] 1e 56 [2] 1c 57 [2] 07 51 [2] 1b 56 [2] 07 79 }

  condition:
    any of them
}