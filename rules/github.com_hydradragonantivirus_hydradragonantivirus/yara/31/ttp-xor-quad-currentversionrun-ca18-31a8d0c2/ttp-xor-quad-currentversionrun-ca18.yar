rule TTP_XOR_QUAD_CurrentVersionRun_ca18 {
  strings:
    $key_ca18 = { 99 77 [2] bd 79 [2] 96 55 [2] b8 77 [2] ac 6c [2] a3 76 [2] bd 6b [2] bf 6a [2] a4 6c [2] b8 6b [2] a4 44 }

  condition:
    any of them
}