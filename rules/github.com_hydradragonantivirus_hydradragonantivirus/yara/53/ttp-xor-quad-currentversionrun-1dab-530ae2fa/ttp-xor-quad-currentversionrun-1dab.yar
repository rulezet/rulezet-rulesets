rule TTP_XOR_QUAD_CurrentVersionRun_1dab {
  strings:
    $key_1dab = { 4e c4 [2] 6a ca [2] 41 e6 [2] 6f c4 [2] 7b df [2] 74 c5 [2] 6a d8 [2] 68 d9 [2] 73 df [2] 6f d8 [2] 73 f7 }

  condition:
    any of them
}