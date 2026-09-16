rule TTP_XOR_QUAD_CurrentVersionRun_e46e {
  strings:
    $key_e46e = { b7 01 [2] 93 0f [2] b8 23 [2] 96 01 [2] 82 1a [2] 8d 00 [2] 93 1d [2] 91 1c [2] 8a 1a [2] 96 1d [2] 8a 32 }

  condition:
    any of them
}