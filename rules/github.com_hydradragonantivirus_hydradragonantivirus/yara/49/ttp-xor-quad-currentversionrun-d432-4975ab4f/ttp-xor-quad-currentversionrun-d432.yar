rule TTP_XOR_QUAD_CurrentVersionRun_d432 {
  strings:
    $key_d432 = { 87 5d [2] a3 53 [2] 88 7f [2] a6 5d [2] b2 46 [2] bd 5c [2] a3 41 [2] a1 40 [2] ba 46 [2] a6 41 [2] ba 6e }

  condition:
    any of them
}