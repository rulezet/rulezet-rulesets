rule TTP_XOR_QUAD_CurrentVersionRun_edb6 {
  strings:
    $key_edb6 = { be d9 [2] 9a d7 [2] b1 fb [2] 9f d9 [2] 8b c2 [2] 84 d8 [2] 9a c5 [2] 98 c4 [2] 83 c2 [2] 9f c5 [2] 83 ea }

  condition:
    any of them
}