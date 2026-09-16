rule TTP_XOR_QUAD_CurrentVersionRun_bbf6 {
  strings:
    $key_bbf6 = { e8 99 [2] cc 97 [2] e7 bb [2] c9 99 [2] dd 82 [2] d2 98 [2] cc 85 [2] ce 84 [2] d5 82 [2] c9 85 [2] d5 aa }

  condition:
    any of them
}