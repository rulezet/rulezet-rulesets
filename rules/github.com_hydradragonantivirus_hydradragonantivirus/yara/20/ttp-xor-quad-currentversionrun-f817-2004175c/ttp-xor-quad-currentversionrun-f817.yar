rule TTP_XOR_QUAD_CurrentVersionRun_f817 {
  strings:
    $key_f817 = { ab 78 [2] 8f 76 [2] a4 5a [2] 8a 78 [2] 9e 63 [2] 91 79 [2] 8f 64 [2] 8d 65 [2] 96 63 [2] 8a 64 [2] 96 4b }

  condition:
    any of them
}