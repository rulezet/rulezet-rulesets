rule TTP_XOR_QUAD_CurrentVersionRun_d44a {
  strings:
    $key_d44a = { 87 25 [2] a3 2b [2] 88 07 [2] a6 25 [2] b2 3e [2] bd 24 [2] a3 39 [2] a1 38 [2] ba 3e [2] a6 39 [2] ba 16 }

  condition:
    any of them
}