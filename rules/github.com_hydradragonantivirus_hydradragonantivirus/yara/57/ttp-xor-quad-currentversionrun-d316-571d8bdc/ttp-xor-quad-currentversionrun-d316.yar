rule TTP_XOR_QUAD_CurrentVersionRun_d316 {
  strings:
    $key_d316 = { 80 79 [2] a4 77 [2] 8f 5b [2] a1 79 [2] b5 62 [2] ba 78 [2] a4 65 [2] a6 64 [2] bd 62 [2] a1 65 [2] bd 4a }

  condition:
    any of them
}