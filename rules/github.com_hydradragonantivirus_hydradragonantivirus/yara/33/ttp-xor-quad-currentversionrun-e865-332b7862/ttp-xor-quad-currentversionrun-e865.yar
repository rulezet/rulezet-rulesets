rule TTP_XOR_QUAD_CurrentVersionRun_e865 {
  strings:
    $key_e865 = { bb 0a [2] 9f 04 [2] b4 28 [2] 9a 0a [2] 8e 11 [2] 81 0b [2] 9f 16 [2] 9d 17 [2] 86 11 [2] 9a 16 [2] 86 39 }

  condition:
    any of them
}