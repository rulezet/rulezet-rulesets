rule TTP_XOR_QUAD_CurrentVersionRun_33b4 {
  strings:
    $key_33b4 = { 60 db [2] 44 d5 [2] 6f f9 [2] 41 db [2] 55 c0 [2] 5a da [2] 44 c7 [2] 46 c6 [2] 5d c0 [2] 41 c7 [2] 5d e8 }

  condition:
    any of them
}