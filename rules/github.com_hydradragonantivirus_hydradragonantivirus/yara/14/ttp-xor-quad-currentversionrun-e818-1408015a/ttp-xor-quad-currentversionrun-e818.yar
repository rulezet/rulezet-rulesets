rule TTP_XOR_QUAD_CurrentVersionRun_e818 {
  strings:
    $key_e818 = { bb 77 [2] 9f 79 [2] b4 55 [2] 9a 77 [2] 8e 6c [2] 81 76 [2] 9f 6b [2] 9d 6a [2] 86 6c [2] 9a 6b [2] 86 44 }

  condition:
    any of them
}