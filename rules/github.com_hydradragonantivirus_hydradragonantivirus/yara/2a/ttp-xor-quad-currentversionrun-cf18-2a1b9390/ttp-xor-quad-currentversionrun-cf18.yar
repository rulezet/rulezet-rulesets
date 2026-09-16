rule TTP_XOR_QUAD_CurrentVersionRun_cf18 {
  strings:
    $key_cf18 = { 9c 77 [2] b8 79 [2] 93 55 [2] bd 77 [2] a9 6c [2] a6 76 [2] b8 6b [2] ba 6a [2] a1 6c [2] bd 6b [2] a1 44 }

  condition:
    any of them
}