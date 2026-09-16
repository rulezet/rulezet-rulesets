rule TTP_XOR_QUAD_CurrentVersionRun_ca27 {
  strings:
    $key_ca27 = { 99 48 [2] bd 46 [2] 96 6a [2] b8 48 [2] ac 53 [2] a3 49 [2] bd 54 [2] bf 55 [2] a4 53 [2] b8 54 [2] a4 7b }

  condition:
    any of them
}