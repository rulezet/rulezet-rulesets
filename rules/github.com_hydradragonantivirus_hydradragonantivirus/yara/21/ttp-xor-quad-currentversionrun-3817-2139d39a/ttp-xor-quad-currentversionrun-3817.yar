rule TTP_XOR_QUAD_CurrentVersionRun_3817 {
  strings:
    $key_3817 = { 6b 78 [2] 4f 76 [2] 64 5a [2] 4a 78 [2] 5e 63 [2] 51 79 [2] 4f 64 [2] 4d 65 [2] 56 63 [2] 4a 64 [2] 56 4b }

  condition:
    any of them
}