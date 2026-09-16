rule TTP_XOR_QUAD_CurrentVersionRun_de10 {
  strings:
    $key_de10 = { 8d 7f [2] a9 71 [2] 82 5d [2] ac 7f [2] b8 64 [2] b7 7e [2] a9 63 [2] ab 62 [2] b0 64 [2] ac 63 [2] b0 4c }

  condition:
    any of them
}