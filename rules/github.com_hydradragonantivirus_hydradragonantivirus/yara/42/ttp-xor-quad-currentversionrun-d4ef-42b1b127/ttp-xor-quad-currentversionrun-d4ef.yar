rule TTP_XOR_QUAD_CurrentVersionRun_d4ef {
  strings:
    $key_d4ef = { 87 80 [2] a3 8e [2] 88 a2 [2] a6 80 [2] b2 9b [2] bd 81 [2] a3 9c [2] a1 9d [2] ba 9b [2] a6 9c [2] ba b3 }

  condition:
    any of them
}