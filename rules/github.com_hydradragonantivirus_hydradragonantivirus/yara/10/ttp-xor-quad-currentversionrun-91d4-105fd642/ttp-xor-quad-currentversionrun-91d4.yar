rule TTP_XOR_QUAD_CurrentVersionRun_91d4 {
  strings:
    $key_91d4 = { c2 bb [2] e6 b5 [2] cd 99 [2] e3 bb [2] f7 a0 [2] f8 ba [2] e6 a7 [2] e4 a6 [2] ff a0 [2] e3 a7 [2] ff 88 }

  condition:
    any of them
}