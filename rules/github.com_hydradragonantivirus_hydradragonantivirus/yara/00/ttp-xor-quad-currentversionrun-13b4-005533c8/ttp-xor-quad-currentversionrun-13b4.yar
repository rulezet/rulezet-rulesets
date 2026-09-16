rule TTP_XOR_QUAD_CurrentVersionRun_13b4 {
  strings:
    $key_13b4 = { 40 db [2] 64 d5 [2] 4f f9 [2] 61 db [2] 75 c0 [2] 7a da [2] 64 c7 [2] 66 c6 [2] 7d c0 [2] 61 c7 [2] 7d e8 }

  condition:
    any of them
}