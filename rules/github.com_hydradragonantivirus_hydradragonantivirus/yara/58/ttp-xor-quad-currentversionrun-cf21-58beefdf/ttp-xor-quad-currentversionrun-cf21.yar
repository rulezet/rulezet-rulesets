rule TTP_XOR_QUAD_CurrentVersionRun_cf21 {
  strings:
    $key_cf21 = { 9c 4e [2] b8 40 [2] 93 6c [2] bd 4e [2] a9 55 [2] a6 4f [2] b8 52 [2] ba 53 [2] a1 55 [2] bd 52 [2] a1 7d }

  condition:
    any of them
}