rule TTP_XOR_QUAD_CurrentVersionRun_e4fd {
  strings:
    $key_e4fd = { b7 92 [2] 93 9c [2] b8 b0 [2] 96 92 [2] 82 89 [2] 8d 93 [2] 93 8e [2] 91 8f [2] 8a 89 [2] 96 8e [2] 8a a1 }

  condition:
    any of them
}