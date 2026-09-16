rule TTP_XOR_QUAD_CurrentVersionRun_e839 {
  strings:
    $key_e839 = { bb 56 [2] 9f 58 [2] b4 74 [2] 9a 56 [2] 8e 4d [2] 81 57 [2] 9f 4a [2] 9d 4b [2] 86 4d [2] 9a 4a [2] 86 65 }

  condition:
    any of them
}