rule TTP_XOR_QUAD_CurrentVersionRun_ca02 {
  strings:
    $key_ca02 = { 99 6d [2] bd 63 [2] 96 4f [2] b8 6d [2] ac 76 [2] a3 6c [2] bd 71 [2] bf 70 [2] a4 76 [2] b8 71 [2] a4 5e }

  condition:
    any of them
}