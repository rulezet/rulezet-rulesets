rule TTP_XOR_QUAD_CurrentVersionRun_f8e9 {
  strings:
    $key_f8e9 = { ab 86 [2] 8f 88 [2] a4 a4 [2] 8a 86 [2] 9e 9d [2] 91 87 [2] 8f 9a [2] 8d 9b [2] 96 9d [2] 8a 9a [2] 96 b5 }

  condition:
    any of them
}