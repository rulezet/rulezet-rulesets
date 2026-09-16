rule TTP_XOR_QUAD_CurrentVersionRun_ca0a {
  strings:
    $key_ca0a = { 99 65 [2] bd 6b [2] 96 47 [2] b8 65 [2] ac 7e [2] a3 64 [2] bd 79 [2] bf 78 [2] a4 7e [2] b8 79 [2] a4 56 }

  condition:
    any of them
}