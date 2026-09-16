rule TTP_XOR_QUAD_CurrentVersionRun_cf3a {
  strings:
    $key_cf3a = { 9c 55 [2] b8 5b [2] 93 77 [2] bd 55 [2] a9 4e [2] a6 54 [2] b8 49 [2] ba 48 [2] a1 4e [2] bd 49 [2] a1 66 }

  condition:
    any of them
}