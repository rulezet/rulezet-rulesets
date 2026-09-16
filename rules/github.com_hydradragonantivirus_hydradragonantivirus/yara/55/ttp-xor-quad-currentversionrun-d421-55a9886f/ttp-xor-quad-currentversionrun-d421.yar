rule TTP_XOR_QUAD_CurrentVersionRun_d421 {
  strings:
    $key_d421 = { 87 4e [2] a3 40 [2] 88 6c [2] a6 4e [2] b2 55 [2] bd 4f [2] a3 52 [2] a1 53 [2] ba 55 [2] a6 52 [2] ba 7d }

  condition:
    any of them
}