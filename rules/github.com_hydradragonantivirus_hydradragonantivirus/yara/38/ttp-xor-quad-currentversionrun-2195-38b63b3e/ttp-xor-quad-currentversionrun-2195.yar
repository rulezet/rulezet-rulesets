rule TTP_XOR_QUAD_CurrentVersionRun_2195 {
  strings:
    $key_2195 = { 72 fa [2] 56 f4 [2] 7d d8 [2] 53 fa [2] 47 e1 [2] 48 fb [2] 56 e6 [2] 54 e7 [2] 4f e1 [2] 53 e6 [2] 4f c9 }

  condition:
    any of them
}