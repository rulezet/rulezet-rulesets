rule TTP_XOR_QUAD_CurrentVersionRun_d471 {
  strings:
    $key_d471 = { 87 1e [2] a3 10 [2] 88 3c [2] a6 1e [2] b2 05 [2] bd 1f [2] a3 02 [2] a1 03 [2] ba 05 [2] a6 02 [2] ba 2d }

  condition:
    any of them
}