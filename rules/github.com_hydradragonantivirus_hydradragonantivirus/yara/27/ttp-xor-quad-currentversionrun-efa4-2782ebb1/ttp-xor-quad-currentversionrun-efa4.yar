rule TTP_XOR_QUAD_CurrentVersionRun_efa4 {
  strings:
    $key_efa4 = { bc cb [2] 98 c5 [2] b3 e9 [2] 9d cb [2] 89 d0 [2] 86 ca [2] 98 d7 [2] 9a d6 [2] 81 d0 [2] 9d d7 [2] 81 f8 }

  condition:
    any of them
}