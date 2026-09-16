rule TTP_XOR_QUAD_CurrentVersionRun_c501 {
  strings:
    $key_c501 = { 96 6e [2] b2 60 [2] 99 4c [2] b7 6e [2] a3 75 [2] ac 6f [2] b2 72 [2] b0 73 [2] ab 75 [2] b7 72 [2] ab 5d }

  condition:
    any of them
}