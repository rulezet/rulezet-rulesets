rule TTP_XOR_QUAD_CurrentVersionRun_d33a {
  strings:
    $key_d33a = { 80 55 [2] a4 5b [2] 8f 77 [2] a1 55 [2] b5 4e [2] ba 54 [2] a4 49 [2] a6 48 [2] bd 4e [2] a1 49 [2] bd 66 }

  condition:
    any of them
}