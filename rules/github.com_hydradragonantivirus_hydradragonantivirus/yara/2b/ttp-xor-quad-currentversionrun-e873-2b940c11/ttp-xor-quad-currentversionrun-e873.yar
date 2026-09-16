rule TTP_XOR_QUAD_CurrentVersionRun_e873 {
  strings:
    $key_e873 = { bb 1c [2] 9f 12 [2] b4 3e [2] 9a 1c [2] 8e 07 [2] 81 1d [2] 9f 00 [2] 9d 01 [2] 86 07 [2] 9a 00 [2] 86 2f }

  condition:
    any of them
}