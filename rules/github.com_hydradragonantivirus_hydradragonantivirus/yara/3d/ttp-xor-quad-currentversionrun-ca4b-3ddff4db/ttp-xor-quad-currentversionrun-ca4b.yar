rule TTP_XOR_QUAD_CurrentVersionRun_ca4b {
  strings:
    $key_ca4b = { 99 24 [2] bd 2a [2] 96 06 [2] b8 24 [2] ac 3f [2] a3 25 [2] bd 38 [2] bf 39 [2] a4 3f [2] b8 38 [2] a4 17 }

  condition:
    any of them
}