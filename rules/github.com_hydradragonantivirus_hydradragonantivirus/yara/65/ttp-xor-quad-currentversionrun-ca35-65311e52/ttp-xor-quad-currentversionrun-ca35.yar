rule TTP_XOR_QUAD_CurrentVersionRun_ca35 {
  strings:
    $key_ca35 = { 99 5a [2] bd 54 [2] 96 78 [2] b8 5a [2] ac 41 [2] a3 5b [2] bd 46 [2] bf 47 [2] a4 41 [2] b8 46 [2] a4 69 }

  condition:
    any of them
}