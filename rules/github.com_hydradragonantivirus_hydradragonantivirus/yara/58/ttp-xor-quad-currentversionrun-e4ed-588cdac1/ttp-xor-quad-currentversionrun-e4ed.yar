rule TTP_XOR_QUAD_CurrentVersionRun_e4ed {
  strings:
    $key_e4ed = { b7 82 [2] 93 8c [2] b8 a0 [2] 96 82 [2] 82 99 [2] 8d 83 [2] 93 9e [2] 91 9f [2] 8a 99 [2] 96 9e [2] 8a b1 }

  condition:
    any of them
}