rule TTP_XOR_QUAD_CurrentVersionRun_ca64 {
  strings:
    $key_ca64 = { 99 0b [2] bd 05 [2] 96 29 [2] b8 0b [2] ac 10 [2] a3 0a [2] bd 17 [2] bf 16 [2] a4 10 [2] b8 17 [2] a4 38 }

  condition:
    any of them
}