rule TTP_XOR_QUAD_CurrentVersionRun_cf10 {
  strings:
    $key_cf10 = { 9c 7f [2] b8 71 [2] 93 5d [2] bd 7f [2] a9 64 [2] a6 7e [2] b8 63 [2] ba 62 [2] a1 64 [2] bd 63 [2] a1 4c }

  condition:
    any of them
}