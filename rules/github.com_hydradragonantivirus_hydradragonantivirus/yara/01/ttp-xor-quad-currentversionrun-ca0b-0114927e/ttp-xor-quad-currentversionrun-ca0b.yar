rule TTP_XOR_QUAD_CurrentVersionRun_ca0b {
  strings:
    $key_ca0b = { 99 64 [2] bd 6a [2] 96 46 [2] b8 64 [2] ac 7f [2] a3 65 [2] bd 78 [2] bf 79 [2] a4 7f [2] b8 78 [2] a4 57 }

  condition:
    any of them
}