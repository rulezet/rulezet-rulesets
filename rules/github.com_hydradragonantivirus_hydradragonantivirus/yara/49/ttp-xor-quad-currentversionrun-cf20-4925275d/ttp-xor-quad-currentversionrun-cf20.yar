rule TTP_XOR_QUAD_CurrentVersionRun_cf20 {
  strings:
    $key_cf20 = { 9c 4f [2] b8 41 [2] 93 6d [2] bd 4f [2] a9 54 [2] a6 4e [2] b8 53 [2] ba 52 [2] a1 54 [2] bd 53 [2] a1 7c }

  condition:
    any of them
}