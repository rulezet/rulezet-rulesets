rule TTP_XOR_QUAD_CurrentVersionRun_e859 {
  strings:
    $key_e859 = { bb 36 [2] 9f 38 [2] b4 14 [2] 9a 36 [2] 8e 2d [2] 81 37 [2] 9f 2a [2] 9d 2b [2] 86 2d [2] 9a 2a [2] 86 05 }

  condition:
    any of them
}