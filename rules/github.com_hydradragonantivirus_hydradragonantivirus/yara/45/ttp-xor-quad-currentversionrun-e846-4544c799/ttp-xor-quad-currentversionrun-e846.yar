rule TTP_XOR_QUAD_CurrentVersionRun_e846 {
  strings:
    $key_e846 = { bb 29 [2] 9f 27 [2] b4 0b [2] 9a 29 [2] 8e 32 [2] 81 28 [2] 9f 35 [2] 9d 34 [2] 86 32 [2] 9a 35 [2] 86 1a }

  condition:
    any of them
}