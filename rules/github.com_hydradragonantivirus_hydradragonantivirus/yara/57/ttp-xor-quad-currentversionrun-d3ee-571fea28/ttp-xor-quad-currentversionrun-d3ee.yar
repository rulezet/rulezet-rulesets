rule TTP_XOR_QUAD_CurrentVersionRun_d3ee {
  strings:
    $key_d3ee = { 80 81 [2] a4 8f [2] 8f a3 [2] a1 81 [2] b5 9a [2] ba 80 [2] a4 9d [2] a6 9c [2] bd 9a [2] a1 9d [2] bd b2 }

  condition:
    any of them
}