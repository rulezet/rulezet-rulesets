rule TTP_XOR_QUAD_CurrentVersionRun_4dab {
  strings:
    $key_4dab = { 1e c4 [2] 3a ca [2] 11 e6 [2] 3f c4 [2] 2b df [2] 24 c5 [2] 3a d8 [2] 38 d9 [2] 23 df [2] 3f d8 [2] 23 f7 }

  condition:
    any of them
}