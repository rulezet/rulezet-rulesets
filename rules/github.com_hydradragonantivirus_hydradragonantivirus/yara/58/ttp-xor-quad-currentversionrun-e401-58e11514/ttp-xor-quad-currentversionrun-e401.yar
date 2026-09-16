rule TTP_XOR_QUAD_CurrentVersionRun_e401 {
  strings:
    $key_e401 = { b7 6e [2] 93 60 [2] b8 4c [2] 96 6e [2] 82 75 [2] 8d 6f [2] 93 72 [2] 91 73 [2] 8a 75 [2] 96 72 [2] 8a 5d }

  condition:
    any of them
}