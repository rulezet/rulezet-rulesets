rule TTP_XOR_QUAD_CurrentVersionRun_d33e {
  strings:
    $key_d33e = { 80 51 [2] a4 5f [2] 8f 73 [2] a1 51 [2] b5 4a [2] ba 50 [2] a4 4d [2] a6 4c [2] bd 4a [2] a1 4d [2] bd 62 }

  condition:
    any of them
}