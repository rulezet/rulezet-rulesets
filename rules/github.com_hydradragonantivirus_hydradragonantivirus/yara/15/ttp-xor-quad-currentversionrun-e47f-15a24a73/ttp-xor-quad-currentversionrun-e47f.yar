rule TTP_XOR_QUAD_CurrentVersionRun_e47f {
  strings:
    $key_e47f = { b7 10 [2] 93 1e [2] b8 32 [2] 96 10 [2] 82 0b [2] 8d 11 [2] 93 0c [2] 91 0d [2] 8a 0b [2] 96 0c [2] 8a 23 }

  condition:
    any of them
}