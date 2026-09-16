rule TTP_XOR_QUAD_CurrentVersionRun_7aa8 {
  strings:
    $key_7aa8 = { 29 c7 [2] 0d c9 [2] 26 e5 [2] 08 c7 [2] 1c dc [2] 13 c6 [2] 0d db [2] 0f da [2] 14 dc [2] 08 db [2] 14 f4 }

  condition:
    any of them
}