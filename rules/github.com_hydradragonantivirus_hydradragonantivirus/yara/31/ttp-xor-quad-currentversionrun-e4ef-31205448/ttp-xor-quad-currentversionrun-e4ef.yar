rule TTP_XOR_QUAD_CurrentVersionRun_e4ef {
  strings:
    $key_e4ef = { b7 80 [2] 93 8e [2] b8 a2 [2] 96 80 [2] 82 9b [2] 8d 81 [2] 93 9c [2] 91 9d [2] 8a 9b [2] 96 9c [2] 8a b3 }

  condition:
    any of them
}