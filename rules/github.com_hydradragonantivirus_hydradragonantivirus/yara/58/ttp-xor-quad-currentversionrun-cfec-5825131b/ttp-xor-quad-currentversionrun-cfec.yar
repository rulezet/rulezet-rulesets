rule TTP_XOR_QUAD_CurrentVersionRun_cfec {
  strings:
    $key_cfec = { 9c 83 [2] b8 8d [2] 93 a1 [2] bd 83 [2] a9 98 [2] a6 82 [2] b8 9f [2] ba 9e [2] a1 98 [2] bd 9f [2] a1 b0 }

  condition:
    any of them
}