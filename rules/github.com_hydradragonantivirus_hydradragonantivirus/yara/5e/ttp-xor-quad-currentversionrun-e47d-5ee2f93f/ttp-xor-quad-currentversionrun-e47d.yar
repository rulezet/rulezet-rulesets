rule TTP_XOR_QUAD_CurrentVersionRun_e47d {
  strings:
    $key_e47d = { b7 12 [2] 93 1c [2] b8 30 [2] 96 12 [2] 82 09 [2] 8d 13 [2] 93 0e [2] 91 0f [2] 8a 09 [2] 96 0e [2] 8a 21 }

  condition:
    any of them
}