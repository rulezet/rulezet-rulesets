rule TTP_XOR_QUAD_CurrentVersionRun_de62 {
  strings:
    $key_de62 = { 8d 0d [2] a9 03 [2] 82 2f [2] ac 0d [2] b8 16 [2] b7 0c [2] a9 11 [2] ab 10 [2] b0 16 [2] ac 11 [2] b0 3e }

  condition:
    any of them
}