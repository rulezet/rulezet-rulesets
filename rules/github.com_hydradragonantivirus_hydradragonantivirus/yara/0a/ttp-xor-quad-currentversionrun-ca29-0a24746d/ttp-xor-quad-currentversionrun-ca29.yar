rule TTP_XOR_QUAD_CurrentVersionRun_ca29 {
  strings:
    $key_ca29 = { 99 46 [2] bd 48 [2] 96 64 [2] b8 46 [2] ac 5d [2] a3 47 [2] bd 5a [2] bf 5b [2] a4 5d [2] b8 5a [2] a4 75 }

  condition:
    any of them
}