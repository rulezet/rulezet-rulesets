rule TTP_XOR_QUAD_CurrentVersionRun_e858 {
  strings:
    $key_e858 = { bb 37 [2] 9f 39 [2] b4 15 [2] 9a 37 [2] 8e 2c [2] 81 36 [2] 9f 2b [2] 9d 2a [2] 86 2c [2] 9a 2b [2] 86 04 }

  condition:
    any of them
}