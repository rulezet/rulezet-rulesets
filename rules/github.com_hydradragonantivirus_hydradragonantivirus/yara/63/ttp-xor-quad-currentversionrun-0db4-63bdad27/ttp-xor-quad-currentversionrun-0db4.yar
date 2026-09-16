rule TTP_XOR_QUAD_CurrentVersionRun_0db4 {
  strings:
    $key_0db4 = { 5e db [2] 7a d5 [2] 51 f9 [2] 7f db [2] 6b c0 [2] 64 da [2] 7a c7 [2] 78 c6 [2] 63 c0 [2] 7f c7 [2] 63 e8 }

  condition:
    any of them
}