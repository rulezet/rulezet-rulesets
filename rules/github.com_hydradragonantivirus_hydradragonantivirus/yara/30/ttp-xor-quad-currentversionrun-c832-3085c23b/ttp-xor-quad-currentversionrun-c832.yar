rule TTP_XOR_QUAD_CurrentVersionRun_c832 {
  strings:
    $key_c832 = { 9b 5d [2] bf 53 [2] 94 7f [2] ba 5d [2] ae 46 [2] a1 5c [2] bf 41 [2] bd 40 [2] a6 46 [2] ba 41 [2] a6 6e }

  condition:
    any of them
}