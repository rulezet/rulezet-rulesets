rule TTP_XOR_QUAD_CurrentVersionRun_e8f8 {
  strings:
    $key_e8f8 = { bb 97 [2] 9f 99 [2] b4 b5 [2] 9a 97 [2] 8e 8c [2] 81 96 [2] 9f 8b [2] 9d 8a [2] 86 8c [2] 9a 8b [2] 86 a4 }

  condition:
    any of them
}