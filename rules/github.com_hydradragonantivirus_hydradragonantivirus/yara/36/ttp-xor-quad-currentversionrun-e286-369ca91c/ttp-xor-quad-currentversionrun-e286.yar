rule TTP_XOR_QUAD_CurrentVersionRun_e286 {
  strings:
    $key_e286 = { b1 e9 [2] 95 e7 [2] be cb [2] 90 e9 [2] 84 f2 [2] 8b e8 [2] 95 f5 [2] 97 f4 [2] 8c f2 [2] 90 f5 [2] 8c da }

  condition:
    any of them
}