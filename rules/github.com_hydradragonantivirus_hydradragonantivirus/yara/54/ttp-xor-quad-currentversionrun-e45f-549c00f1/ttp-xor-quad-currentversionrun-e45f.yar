rule TTP_XOR_QUAD_CurrentVersionRun_e45f {
  strings:
    $key_e45f = { b7 30 [2] 93 3e [2] b8 12 [2] 96 30 [2] 82 2b [2] 8d 31 [2] 93 2c [2] 91 2d [2] 8a 2b [2] 96 2c [2] 8a 03 }

  condition:
    any of them
}