rule TTP_XOR_QUAD_CurrentVersionRun_f8f8 {
  strings:
    $key_f8f8 = { ab 97 [2] 8f 99 [2] a4 b5 [2] 8a 97 [2] 9e 8c [2] 91 96 [2] 8f 8b [2] 8d 8a [2] 96 8c [2] 8a 8b [2] 96 a4 }

  condition:
    any of them
}