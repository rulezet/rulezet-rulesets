rule TTP_XOR_QUAD_CurrentVersionRun_fda8 {
  strings:
    $key_fda8 = { ae c7 [2] 8a c9 [2] a1 e5 [2] 8f c7 [2] 9b dc [2] 94 c6 [2] 8a db [2] 88 da [2] 93 dc [2] 8f db [2] 93 f4 }

  condition:
    any of them
}