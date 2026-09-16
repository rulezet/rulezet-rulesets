rule TTP_XOR_QUAD_CurrentVersionRun_3917 {
  strings:
    $key_3917 = { 6a 78 [2] 4e 76 [2] 65 5a [2] 4b 78 [2] 5f 63 [2] 50 79 [2] 4e 64 [2] 4c 65 [2] 57 63 [2] 4b 64 [2] 57 4b }

  condition:
    any of them
}