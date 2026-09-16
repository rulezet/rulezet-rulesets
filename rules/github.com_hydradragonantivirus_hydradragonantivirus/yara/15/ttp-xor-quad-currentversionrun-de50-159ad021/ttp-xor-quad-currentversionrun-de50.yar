rule TTP_XOR_QUAD_CurrentVersionRun_de50 {
  strings:
    $key_de50 = { 8d 3f [2] a9 31 [2] 82 1d [2] ac 3f [2] b8 24 [2] b7 3e [2] a9 23 [2] ab 22 [2] b0 24 [2] ac 23 [2] b0 0c }

  condition:
    any of them
}