rule TTP_XOR_QUAD_CurrentVersionRun_e6b7 {
  strings:
    $key_e6b7 = { b5 d8 [2] 91 d6 [2] ba fa [2] 94 d8 [2] 80 c3 [2] 8f d9 [2] 91 c4 [2] 93 c5 [2] 88 c3 [2] 94 c4 [2] 88 eb }

  condition:
    any of them
}