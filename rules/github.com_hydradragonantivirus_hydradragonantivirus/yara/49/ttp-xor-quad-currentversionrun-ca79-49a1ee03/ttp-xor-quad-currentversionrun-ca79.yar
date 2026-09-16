rule TTP_XOR_QUAD_CurrentVersionRun_ca79 {
  strings:
    $key_ca79 = { 99 16 [2] bd 18 [2] 96 34 [2] b8 16 [2] ac 0d [2] a3 17 [2] bd 0a [2] bf 0b [2] a4 0d [2] b8 0a [2] a4 25 }

  condition:
    any of them
}