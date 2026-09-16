rule TTP_XOR_QUAD_CurrentVersionRun_cf5a {
  strings:
    $key_cf5a = { 9c 35 [2] b8 3b [2] 93 17 [2] bd 35 [2] a9 2e [2] a6 34 [2] b8 29 [2] ba 28 [2] a1 2e [2] bd 29 [2] a1 06 }

  condition:
    any of them
}