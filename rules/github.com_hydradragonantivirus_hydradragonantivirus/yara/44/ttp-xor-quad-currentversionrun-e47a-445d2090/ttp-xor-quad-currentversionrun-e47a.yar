rule TTP_XOR_QUAD_CurrentVersionRun_e47a {
  strings:
    $key_e47a = { b7 15 [2] 93 1b [2] b8 37 [2] 96 15 [2] 82 0e [2] 8d 14 [2] 93 09 [2] 91 08 [2] 8a 0e [2] 96 09 [2] 8a 26 }

  condition:
    any of them
}