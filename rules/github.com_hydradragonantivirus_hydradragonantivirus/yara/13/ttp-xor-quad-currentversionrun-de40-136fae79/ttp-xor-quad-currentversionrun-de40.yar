rule TTP_XOR_QUAD_CurrentVersionRun_de40 {
  strings:
    $key_de40 = { 8d 2f [2] a9 21 [2] 82 0d [2] ac 2f [2] b8 34 [2] b7 2e [2] a9 33 [2] ab 32 [2] b0 34 [2] ac 33 [2] b0 1c }

  condition:
    any of them
}