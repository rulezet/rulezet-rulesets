rule TTP_XOR_QUAD_CurrentVersionRun_de0c {
  strings:
    $key_de0c = { 8d 63 [2] a9 6d [2] 82 41 [2] ac 63 [2] b8 78 [2] b7 62 [2] a9 7f [2] ab 7e [2] b0 78 [2] ac 7f [2] b0 50 }

  condition:
    any of them
}