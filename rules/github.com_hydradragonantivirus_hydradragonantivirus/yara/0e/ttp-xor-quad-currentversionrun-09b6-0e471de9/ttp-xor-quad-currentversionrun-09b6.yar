rule TTP_XOR_QUAD_CurrentVersionRun_09b6 {
  strings:
    $key_09b6 = { 5a d9 [2] 7e d7 [2] 55 fb [2] 7b d9 [2] 6f c2 [2] 60 d8 [2] 7e c5 [2] 7c c4 [2] 67 c2 [2] 7b c5 [2] 67 ea }

  condition:
    any of them
}