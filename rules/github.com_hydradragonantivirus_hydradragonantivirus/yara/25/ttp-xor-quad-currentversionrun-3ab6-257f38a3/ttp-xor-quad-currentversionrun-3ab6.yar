rule TTP_XOR_QUAD_CurrentVersionRun_3ab6 {
  strings:
    $key_3ab6 = { 69 d9 [2] 4d d7 [2] 66 fb [2] 48 d9 [2] 5c c2 [2] 53 d8 [2] 4d c5 [2] 4f c4 [2] 54 c2 [2] 48 c5 [2] 54 ea }

  condition:
    any of them
}