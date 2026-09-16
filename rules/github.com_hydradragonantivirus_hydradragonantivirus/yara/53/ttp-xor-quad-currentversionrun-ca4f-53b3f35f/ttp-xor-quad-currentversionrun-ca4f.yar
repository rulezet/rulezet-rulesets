rule TTP_XOR_QUAD_CurrentVersionRun_ca4f {
  strings:
    $key_ca4f = { 99 20 [2] bd 2e [2] 96 02 [2] b8 20 [2] ac 3b [2] a3 21 [2] bd 3c [2] bf 3d [2] a4 3b [2] b8 3c [2] a4 13 }

  condition:
    any of them
}