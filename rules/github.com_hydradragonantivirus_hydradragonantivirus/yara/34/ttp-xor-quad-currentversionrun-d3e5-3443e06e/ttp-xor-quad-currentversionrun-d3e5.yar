rule TTP_XOR_QUAD_CurrentVersionRun_d3e5 {
  strings:
    $key_d3e5 = { 80 8a [2] a4 84 [2] 8f a8 [2] a1 8a [2] b5 91 [2] ba 8b [2] a4 96 [2] a6 97 [2] bd 91 [2] a1 96 [2] bd b9 }

  condition:
    any of them
}