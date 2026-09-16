rule TTP_XOR_QUAD_CurrentVersionRun_fcb6 {
  strings:
    $key_fcb6 = { af d9 [2] 8b d7 [2] a0 fb [2] 8e d9 [2] 9a c2 [2] 95 d8 [2] 8b c5 [2] 89 c4 [2] 92 c2 [2] 8e c5 [2] 92 ea }

  condition:
    any of them
}