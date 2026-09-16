rule TTP_XOR_QUAD_CurrentVersionRun_d4e9 {
  strings:
    $key_d4e9 = { 87 86 [2] a3 88 [2] 88 a4 [2] a6 86 [2] b2 9d [2] bd 87 [2] a3 9a [2] a1 9b [2] ba 9d [2] a6 9a [2] ba b5 }

  condition:
    any of them
}