rule TTP_XOR_QUAD_CurrentVersionRun_d310 {
  strings:
    $key_d310 = { 80 7f [2] a4 71 [2] 8f 5d [2] a1 7f [2] b5 64 [2] ba 7e [2] a4 63 [2] a6 62 [2] bd 64 [2] a1 63 [2] bd 4c }

  condition:
    any of them
}