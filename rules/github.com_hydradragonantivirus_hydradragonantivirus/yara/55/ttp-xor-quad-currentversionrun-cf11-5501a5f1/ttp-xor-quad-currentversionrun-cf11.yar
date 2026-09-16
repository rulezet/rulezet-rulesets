rule TTP_XOR_QUAD_CurrentVersionRun_cf11 {
  strings:
    $key_cf11 = { 9c 7e [2] b8 70 [2] 93 5c [2] bd 7e [2] a9 65 [2] a6 7f [2] b8 62 [2] ba 63 [2] a1 65 [2] bd 62 [2] a1 4d }

  condition:
    any of them
}