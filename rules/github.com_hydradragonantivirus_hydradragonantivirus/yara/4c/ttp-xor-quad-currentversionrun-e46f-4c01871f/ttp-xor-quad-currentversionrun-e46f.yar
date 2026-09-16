rule TTP_XOR_QUAD_CurrentVersionRun_e46f {
  strings:
    $key_e46f = { b7 00 [2] 93 0e [2] b8 22 [2] 96 00 [2] 82 1b [2] 8d 01 [2] 93 1c [2] 91 1d [2] 8a 1b [2] 96 1c [2] 8a 33 }

  condition:
    any of them
}