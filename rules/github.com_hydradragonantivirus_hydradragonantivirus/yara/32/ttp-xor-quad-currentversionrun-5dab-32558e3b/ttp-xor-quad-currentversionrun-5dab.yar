rule TTP_XOR_QUAD_CurrentVersionRun_5dab {
  strings:
    $key_5dab = { 0e c4 [2] 2a ca [2] 01 e6 [2] 2f c4 [2] 3b df [2] 34 c5 [2] 2a d8 [2] 28 d9 [2] 33 df [2] 2f d8 [2] 33 f7 }

  condition:
    any of them
}