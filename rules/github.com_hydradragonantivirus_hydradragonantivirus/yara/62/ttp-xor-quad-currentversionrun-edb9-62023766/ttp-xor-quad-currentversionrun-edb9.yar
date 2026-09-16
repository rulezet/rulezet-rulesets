rule TTP_XOR_QUAD_CurrentVersionRun_edb9 {
  strings:
    $key_edb9 = { be d6 [2] 9a d8 [2] b1 f4 [2] 9f d6 [2] 8b cd [2] 84 d7 [2] 9a ca [2] 98 cb [2] 83 cd [2] 9f ca [2] 83 e5 }

  condition:
    any of them
}