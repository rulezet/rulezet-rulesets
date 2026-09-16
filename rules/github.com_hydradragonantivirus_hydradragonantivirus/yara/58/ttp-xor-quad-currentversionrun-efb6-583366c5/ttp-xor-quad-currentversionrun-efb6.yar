rule TTP_XOR_QUAD_CurrentVersionRun_efb6 {
  strings:
    $key_efb6 = { bc d9 [2] 98 d7 [2] b3 fb [2] 9d d9 [2] 89 c2 [2] 86 d8 [2] 98 c5 [2] 9a c4 [2] 81 c2 [2] 9d c5 [2] 81 ea }

  condition:
    any of them
}