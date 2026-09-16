rule TTP_XOR_QUAD_CurrentVersionRun_cf4a {
  strings:
    $key_cf4a = { 9c 25 [2] b8 2b [2] 93 07 [2] bd 25 [2] a9 3e [2] a6 24 [2] b8 39 [2] ba 38 [2] a1 3e [2] bd 39 [2] a1 16 }

  condition:
    any of them
}