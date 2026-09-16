rule TTP_XOR_QUAD_CurrentVersionRun_e844 {
  strings:
    $key_e844 = { bb 2b [2] 9f 25 [2] b4 09 [2] 9a 2b [2] 8e 30 [2] 81 2a [2] 9f 37 [2] 9d 36 [2] 86 30 [2] 9a 37 [2] 86 18 }

  condition:
    any of them
}