rule TTP_XOR_QUAD_CurrentVersionRun_ca1f {
  strings:
    $key_ca1f = { 99 70 [2] bd 7e [2] 96 52 [2] b8 70 [2] ac 6b [2] a3 71 [2] bd 6c [2] bf 6d [2] a4 6b [2] b8 6c [2] a4 43 }

  condition:
    any of them
}