rule TTP_XOR_QUAD_CurrentVersionRun_ca4a {
  strings:
    $key_ca4a = { 99 25 [2] bd 2b [2] 96 07 [2] b8 25 [2] ac 3e [2] a3 24 [2] bd 39 [2] bf 38 [2] a4 3e [2] b8 39 [2] a4 16 }

  condition:
    any of them
}