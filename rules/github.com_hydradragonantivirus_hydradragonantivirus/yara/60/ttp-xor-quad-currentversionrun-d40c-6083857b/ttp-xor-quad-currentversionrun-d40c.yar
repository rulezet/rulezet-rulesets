rule TTP_XOR_QUAD_CurrentVersionRun_d40c {
  strings:
    $key_d40c = { 87 63 [2] a3 6d [2] 88 41 [2] a6 63 [2] b2 78 [2] bd 62 [2] a3 7f [2] a1 7e [2] ba 78 [2] a6 7f [2] ba 50 }

  condition:
    any of them
}