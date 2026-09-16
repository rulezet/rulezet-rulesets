rule TTP_XOR_QUAD_CurrentVersionRun_cf0c {
  strings:
    $key_cf0c = { 9c 63 [2] b8 6d [2] 93 41 [2] bd 63 [2] a9 78 [2] a6 62 [2] b8 7f [2] ba 7e [2] a1 78 [2] bd 7f [2] a1 50 }

  condition:
    any of them
}