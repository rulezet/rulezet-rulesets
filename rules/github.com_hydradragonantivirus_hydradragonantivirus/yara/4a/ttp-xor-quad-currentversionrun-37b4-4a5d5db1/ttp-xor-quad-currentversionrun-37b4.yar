rule TTP_XOR_QUAD_CurrentVersionRun_37b4 {
  strings:
    $key_37b4 = { 64 db [2] 40 d5 [2] 6b f9 [2] 45 db [2] 51 c0 [2] 5e da [2] 40 c7 [2] 42 c6 [2] 59 c0 [2] 45 c7 [2] 59 e8 }

  condition:
    any of them
}