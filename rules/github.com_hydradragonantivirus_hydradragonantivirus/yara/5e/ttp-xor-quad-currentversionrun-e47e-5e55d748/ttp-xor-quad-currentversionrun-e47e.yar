rule TTP_XOR_QUAD_CurrentVersionRun_e47e {
  strings:
    $key_e47e = { b7 11 [2] 93 1f [2] b8 33 [2] 96 11 [2] 82 0a [2] 8d 10 [2] 93 0d [2] 91 0c [2] 8a 0a [2] 96 0d [2] 8a 22 }

  condition:
    any of them
}