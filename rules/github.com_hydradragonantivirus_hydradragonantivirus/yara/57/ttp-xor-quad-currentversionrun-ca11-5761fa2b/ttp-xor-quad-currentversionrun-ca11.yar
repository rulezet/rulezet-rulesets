rule TTP_XOR_QUAD_CurrentVersionRun_ca11 {
  strings:
    $key_ca11 = { 99 7e [2] bd 70 [2] 96 5c [2] b8 7e [2] ac 65 [2] a3 7f [2] bd 62 [2] bf 63 [2] a4 65 [2] b8 62 [2] a4 4d }

  condition:
    any of them
}