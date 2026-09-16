rule TTP_XOR_QUAD_CurrentVersionRun_cf22 {
  strings:
    $key_cf22 = { 9c 4d [2] b8 43 [2] 93 6f [2] bd 4d [2] a9 56 [2] a6 4c [2] b8 51 [2] ba 50 [2] a1 56 [2] bd 51 [2] a1 7e }

  condition:
    any of them
}