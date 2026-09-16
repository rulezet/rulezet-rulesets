rule TTP_XOR_QUAD_CurrentVersionRun_e442 {
  strings:
    $key_e442 = { b7 2d [2] 93 23 [2] b8 0f [2] 96 2d [2] 82 36 [2] 8d 2c [2] 93 31 [2] 91 30 [2] 8a 36 [2] 96 31 [2] 8a 1e }

  condition:
    any of them
}