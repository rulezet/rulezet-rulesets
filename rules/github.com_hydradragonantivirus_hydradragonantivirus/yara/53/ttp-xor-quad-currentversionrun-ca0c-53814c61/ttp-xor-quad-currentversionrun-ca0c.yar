rule TTP_XOR_QUAD_CurrentVersionRun_ca0c {
  strings:
    $key_ca0c = { 99 63 [2] bd 6d [2] 96 41 [2] b8 63 [2] ac 78 [2] a3 62 [2] bd 7f [2] bf 7e [2] a4 78 [2] b8 7f [2] a4 50 }

  condition:
    any of them
}