rule TTP_XOR_QUAD_CurrentVersionRun_ca34 {
  strings:
    $key_ca34 = { 99 5b [2] bd 55 [2] 96 79 [2] b8 5b [2] ac 40 [2] a3 5a [2] bd 47 [2] bf 46 [2] a4 40 [2] b8 47 [2] a4 68 }

  condition:
    any of them
}