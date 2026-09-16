rule TTP_XOR_QUAD_CurrentVersionRun_ca09 {
  strings:
    $key_ca09 = { 99 66 [2] bd 68 [2] 96 44 [2] b8 66 [2] ac 7d [2] a3 67 [2] bd 7a [2] bf 7b [2] a4 7d [2] b8 7a [2] a4 55 }

  condition:
    any of them
}