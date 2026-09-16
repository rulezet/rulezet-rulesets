rule TTP_XOR_QUAD_CurrentVersionRun_e45a {
  strings:
    $key_e45a = { b7 35 [2] 93 3b [2] b8 17 [2] 96 35 [2] 82 2e [2] 8d 34 [2] 93 29 [2] 91 28 [2] 8a 2e [2] 96 29 [2] 8a 06 }

  condition:
    any of them
}