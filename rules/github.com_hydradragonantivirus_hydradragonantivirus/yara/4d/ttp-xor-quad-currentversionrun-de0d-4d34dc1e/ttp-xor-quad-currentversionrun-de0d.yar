rule TTP_XOR_QUAD_CurrentVersionRun_de0d {
  strings:
    $key_de0d = { 8d 62 [2] a9 6c [2] 82 40 [2] ac 62 [2] b8 79 [2] b7 63 [2] a9 7e [2] ab 7f [2] b0 79 [2] ac 7e [2] b0 51 }

  condition:
    any of them
}