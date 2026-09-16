rule TTP_XOR_QUAD_CurrentVersionRun_ca2f {
  strings:
    $key_ca2f = { 99 40 [2] bd 4e [2] 96 62 [2] b8 40 [2] ac 5b [2] a3 41 [2] bd 5c [2] bf 5d [2] a4 5b [2] b8 5c [2] a4 73 }

  condition:
    any of them
}