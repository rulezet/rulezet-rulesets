rule TTP_XOR_QUAD_CurrentVersionRun_cf7f {
  strings:
    $key_cf7f = { 9c 10 [2] b8 1e [2] 93 32 [2] bd 10 [2] a9 0b [2] a6 11 [2] b8 0c [2] ba 0d [2] a1 0b [2] bd 0c [2] a1 23 }

  condition:
    any of them
}