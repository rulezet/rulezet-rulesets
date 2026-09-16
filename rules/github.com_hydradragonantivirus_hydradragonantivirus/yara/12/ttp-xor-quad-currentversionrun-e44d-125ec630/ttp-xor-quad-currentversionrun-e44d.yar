rule TTP_XOR_QUAD_CurrentVersionRun_e44d {
  strings:
    $key_e44d = { b7 22 [2] 93 2c [2] b8 00 [2] 96 22 [2] 82 39 [2] 8d 23 [2] 93 3e [2] 91 3f [2] 8a 39 [2] 96 3e [2] 8a 11 }

  condition:
    any of them
}