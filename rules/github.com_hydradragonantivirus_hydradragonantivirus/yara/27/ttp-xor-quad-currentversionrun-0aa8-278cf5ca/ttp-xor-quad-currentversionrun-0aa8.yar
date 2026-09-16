rule TTP_XOR_QUAD_CurrentVersionRun_0aa8 {
  strings:
    $key_0aa8 = { 59 c7 [2] 7d c9 [2] 56 e5 [2] 78 c7 [2] 6c dc [2] 63 c6 [2] 7d db [2] 7f da [2] 64 dc [2] 78 db [2] 64 f4 }

  condition:
    any of them
}