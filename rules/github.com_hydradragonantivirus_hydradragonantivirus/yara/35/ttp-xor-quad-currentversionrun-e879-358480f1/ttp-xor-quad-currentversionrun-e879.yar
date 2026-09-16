rule TTP_XOR_QUAD_CurrentVersionRun_e879 {
  strings:
    $key_e879 = { bb 16 [2] 9f 18 [2] b4 34 [2] 9a 16 [2] 8e 0d [2] 81 17 [2] 9f 0a [2] 9d 0b [2] 86 0d [2] 9a 0a [2] 86 25 }

  condition:
    any of them
}