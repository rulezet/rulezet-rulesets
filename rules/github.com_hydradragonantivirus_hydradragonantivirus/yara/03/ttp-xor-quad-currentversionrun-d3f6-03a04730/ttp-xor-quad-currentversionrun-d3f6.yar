rule TTP_XOR_QUAD_CurrentVersionRun_d3f6 {
  strings:
    $key_d3f6 = { 80 99 [2] a4 97 [2] 8f bb [2] a1 99 [2] b5 82 [2] ba 98 [2] a4 85 [2] a6 84 [2] bd 82 [2] a1 85 [2] bd aa }

  condition:
    any of them
}