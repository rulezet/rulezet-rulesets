rule TTP_XOR_QUAD_CurrentVersionRun_e808 {
  strings:
    $key_e808 = { bb 67 [2] 9f 69 [2] b4 45 [2] 9a 67 [2] 8e 7c [2] 81 66 [2] 9f 7b [2] 9d 7a [2] 86 7c [2] 9a 7b [2] 86 54 }

  condition:
    any of them
}