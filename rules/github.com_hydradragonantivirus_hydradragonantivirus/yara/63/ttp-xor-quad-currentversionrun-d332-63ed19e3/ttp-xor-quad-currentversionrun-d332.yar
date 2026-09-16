rule TTP_XOR_QUAD_CurrentVersionRun_d332 {
  strings:
    $key_d332 = { 80 5d [2] a4 53 [2] 8f 7f [2] a1 5d [2] b5 46 [2] ba 5c [2] a4 41 [2] a6 40 [2] bd 46 [2] a1 41 [2] bd 6e }

  condition:
    any of them
}