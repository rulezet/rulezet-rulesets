rule TTP_XOR_QUAD_CurrentVersionRun_3fbb {
  strings:
    $key_3fbb = { 6c d4 [2] 48 da [2] 63 f6 [2] 4d d4 [2] 59 cf [2] 56 d5 [2] 48 c8 [2] 4a c9 [2] 51 cf [2] 4d c8 [2] 51 e7 }

  condition:
    any of them
}