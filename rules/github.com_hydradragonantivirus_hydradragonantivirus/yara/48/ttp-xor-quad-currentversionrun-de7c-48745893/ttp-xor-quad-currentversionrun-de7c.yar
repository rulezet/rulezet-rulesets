rule TTP_XOR_QUAD_CurrentVersionRun_de7c {
  strings:
    $key_de7c = { 8d 13 [2] a9 1d [2] 82 31 [2] ac 13 [2] b8 08 [2] b7 12 [2] a9 0f [2] ab 0e [2] b0 08 [2] ac 0f [2] b0 20 }

  condition:
    any of them
}