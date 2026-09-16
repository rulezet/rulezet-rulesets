rule TTP_XOR_QUAD_CurrentVersionRun_1917 {
  strings:
    $key_1917 = { 4a 78 [2] 6e 76 [2] 45 5a [2] 6b 78 [2] 7f 63 [2] 70 79 [2] 6e 64 [2] 6c 65 [2] 77 63 [2] 6b 64 [2] 77 4b }

  condition:
    any of them
}