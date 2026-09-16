rule TTP_XOR_QUAD_CurrentVersionRun_0dab {
  strings:
    $key_0dab = { 5e c4 [2] 7a ca [2] 51 e6 [2] 7f c4 [2] 6b df [2] 64 c5 [2] 7a d8 [2] 78 d9 [2] 63 df [2] 7f d8 [2] 63 f7 }

  condition:
    any of them
}