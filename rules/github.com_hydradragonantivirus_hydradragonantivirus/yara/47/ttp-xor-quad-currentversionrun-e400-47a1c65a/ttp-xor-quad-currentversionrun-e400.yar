rule TTP_XOR_QUAD_CurrentVersionRun_e400 {
  strings:
    $key_e400 = { b7 6f [2] 93 61 [2] b8 4d [2] 96 6f [2] 82 74 [2] 8d 6e [2] 93 73 [2] 91 72 [2] 8a 74 [2] 96 73 [2] 8a 5c }

  condition:
    any of them
}