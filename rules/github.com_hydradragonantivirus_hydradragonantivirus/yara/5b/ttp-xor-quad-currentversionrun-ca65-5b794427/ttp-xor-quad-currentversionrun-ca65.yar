rule TTP_XOR_QUAD_CurrentVersionRun_ca65 {
  strings:
    $key_ca65 = { 99 0a [2] bd 04 [2] 96 28 [2] b8 0a [2] ac 11 [2] a3 0b [2] bd 16 [2] bf 17 [2] a4 11 [2] b8 16 [2] a4 39 }

  condition:
    any of them
}