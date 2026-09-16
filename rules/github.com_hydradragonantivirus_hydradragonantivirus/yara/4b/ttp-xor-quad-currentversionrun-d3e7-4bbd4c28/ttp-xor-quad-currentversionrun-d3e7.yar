rule TTP_XOR_QUAD_CurrentVersionRun_d3e7 {
  strings:
    $key_d3e7 = { 80 88 [2] a4 86 [2] 8f aa [2] a1 88 [2] b5 93 [2] ba 89 [2] a4 94 [2] a6 95 [2] bd 93 [2] a1 94 [2] bd bb }

  condition:
    any of them
}