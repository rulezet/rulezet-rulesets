rule TTP_XOR_QUAD_CurrentVersionRun_91d5 {
  strings:
    $key_91d5 = { c2 ba [2] e6 b4 [2] cd 98 [2] e3 ba [2] f7 a1 [2] f8 bb [2] e6 a6 [2] e4 a7 [2] ff a1 [2] e3 a6 [2] ff 89 }

  condition:
    any of them
}