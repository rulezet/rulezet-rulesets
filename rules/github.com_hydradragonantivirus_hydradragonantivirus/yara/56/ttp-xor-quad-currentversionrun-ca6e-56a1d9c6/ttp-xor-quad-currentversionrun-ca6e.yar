rule TTP_XOR_QUAD_CurrentVersionRun_ca6e {
  strings:
    $key_ca6e = { 99 01 [2] bd 0f [2] 96 23 [2] b8 01 [2] ac 1a [2] a3 00 [2] bd 1d [2] bf 1c [2] a4 1a [2] b8 1d [2] a4 32 }

  condition:
    any of them
}