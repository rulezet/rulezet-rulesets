rule TTP_XOR_QUAD_CurrentVersionRun_ca2e {
  strings:
    $key_ca2e = { 99 41 [2] bd 4f [2] 96 63 [2] b8 41 [2] ac 5a [2] a3 40 [2] bd 5d [2] bf 5c [2] a4 5a [2] b8 5d [2] a4 72 }

  condition:
    any of them
}