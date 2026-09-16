rule TTP_XOR_QUAD_CurrentVersionRun_d3ea {
  strings:
    $key_d3ea = { 80 85 [2] a4 8b [2] 8f a7 [2] a1 85 [2] b5 9e [2] ba 84 [2] a4 99 [2] a6 98 [2] bd 9e [2] a1 99 [2] bd b6 }

  condition:
    any of them
}