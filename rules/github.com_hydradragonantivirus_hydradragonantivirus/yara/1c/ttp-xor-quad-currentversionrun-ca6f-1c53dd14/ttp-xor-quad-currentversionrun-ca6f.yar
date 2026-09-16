rule TTP_XOR_QUAD_CurrentVersionRun_ca6f {
  strings:
    $key_ca6f = { 99 00 [2] bd 0e [2] 96 22 [2] b8 00 [2] ac 1b [2] a3 01 [2] bd 1c [2] bf 1d [2] a4 1b [2] b8 1c [2] a4 33 }

  condition:
    any of them
}