rule TTP_XOR_QUAD_CurrentVersionRun_f8e4 {
  strings:
    $key_f8e4 = { ab 8b [2] 8f 85 [2] a4 a9 [2] 8a 8b [2] 9e 90 [2] 91 8a [2] 8f 97 [2] 8d 96 [2] 96 90 [2] 8a 97 [2] 96 b8 }

  condition:
    any of them
}