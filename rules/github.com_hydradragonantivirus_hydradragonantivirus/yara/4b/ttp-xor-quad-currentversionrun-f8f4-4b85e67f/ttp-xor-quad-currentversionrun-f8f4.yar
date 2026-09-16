rule TTP_XOR_QUAD_CurrentVersionRun_f8f4 {
  strings:
    $key_f8f4 = { ab 9b [2] 8f 95 [2] a4 b9 [2] 8a 9b [2] 9e 80 [2] 91 9a [2] 8f 87 [2] 8d 86 [2] 96 80 [2] 8a 87 [2] 96 a8 }

  condition:
    any of them
}