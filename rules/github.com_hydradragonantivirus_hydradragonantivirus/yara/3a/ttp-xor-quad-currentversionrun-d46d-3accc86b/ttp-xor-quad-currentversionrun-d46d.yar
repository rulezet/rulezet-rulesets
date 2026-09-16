rule TTP_XOR_QUAD_CurrentVersionRun_d46d {
  strings:
    $key_d46d = { 87 02 [2] a3 0c [2] 88 20 [2] a6 02 [2] b2 19 [2] bd 03 [2] a3 1e [2] a1 1f [2] ba 19 [2] a6 1e [2] ba 31 }

  condition:
    any of them
}