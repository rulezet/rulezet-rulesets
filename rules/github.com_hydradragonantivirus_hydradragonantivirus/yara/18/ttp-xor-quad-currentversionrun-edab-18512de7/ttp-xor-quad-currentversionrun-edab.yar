rule TTP_XOR_QUAD_CurrentVersionRun_edab {
  strings:
    $key_edab = { be c4 [2] 9a ca [2] b1 e6 [2] 9f c4 [2] 8b df [2] 84 c5 [2] 9a d8 [2] 98 d9 [2] 83 df [2] 9f d8 [2] 83 f7 }

  condition:
    any of them
}