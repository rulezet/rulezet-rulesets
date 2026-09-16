rule TTP_XOR_QUAD_CurrentVersionRun_d3e9 {
  strings:
    $key_d3e9 = { 80 86 [2] a4 88 [2] 8f a4 [2] a1 86 [2] b5 9d [2] ba 87 [2] a4 9a [2] a6 9b [2] bd 9d [2] a1 9a [2] bd b5 }

  condition:
    any of them
}