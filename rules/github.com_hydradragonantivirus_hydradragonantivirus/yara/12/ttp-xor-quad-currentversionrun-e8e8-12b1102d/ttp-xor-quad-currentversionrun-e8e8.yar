rule TTP_XOR_QUAD_CurrentVersionRun_e8e8 {
  strings:
    $key_e8e8 = { bb 87 [2] 9f 89 [2] b4 a5 [2] 9a 87 [2] 8e 9c [2] 81 86 [2] 9f 9b [2] 9d 9a [2] 86 9c [2] 9a 9b [2] 86 b4 }

  condition:
    any of them
}