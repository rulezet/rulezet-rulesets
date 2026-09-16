rule TTP_XOR_QUAD_CurrentVersionRun_d43a {
  strings:
    $key_d43a = { 87 55 [2] a3 5b [2] 88 77 [2] a6 55 [2] b2 4e [2] bd 54 [2] a3 49 [2] a1 48 [2] ba 4e [2] a6 49 [2] ba 66 }

  condition:
    any of them
}