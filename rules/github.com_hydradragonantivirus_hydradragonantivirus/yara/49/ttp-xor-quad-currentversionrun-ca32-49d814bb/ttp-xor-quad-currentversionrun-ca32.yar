rule TTP_XOR_QUAD_CurrentVersionRun_ca32 {
  strings:
    $key_ca32 = { 99 5d [2] bd 53 [2] 96 7f [2] b8 5d [2] ac 46 [2] a3 5c [2] bd 41 [2] bf 40 [2] a4 46 [2] b8 41 [2] a4 6e }

  condition:
    any of them
}