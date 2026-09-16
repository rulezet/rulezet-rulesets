rule TTP_XOR_QUAD_CurrentVersionRun_e878 {
  strings:
    $key_e878 = { bb 17 [2] 9f 19 [2] b4 35 [2] 9a 17 [2] 8e 0c [2] 81 16 [2] 9f 0b [2] 9d 0a [2] 86 0c [2] 9a 0b [2] 86 24 }

  condition:
    any of them
}