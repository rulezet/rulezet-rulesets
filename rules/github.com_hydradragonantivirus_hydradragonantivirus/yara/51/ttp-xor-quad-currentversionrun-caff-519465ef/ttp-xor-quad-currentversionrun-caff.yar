rule TTP_XOR_QUAD_CurrentVersionRun_caff {
  strings:
    $key_caff = { 99 90 [2] bd 9e [2] 96 b2 [2] b8 90 [2] ac 8b [2] a3 91 [2] bd 8c [2] bf 8d [2] a4 8b [2] b8 8c [2] a4 a3 }

  condition:
    any of them
}