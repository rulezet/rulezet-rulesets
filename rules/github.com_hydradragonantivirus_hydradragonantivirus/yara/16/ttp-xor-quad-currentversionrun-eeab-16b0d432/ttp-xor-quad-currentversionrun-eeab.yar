rule TTP_XOR_QUAD_CurrentVersionRun_eeab {
  strings:
    $key_eeab = { bd c4 [2] 99 ca [2] b2 e6 [2] 9c c4 [2] 88 df [2] 87 c5 [2] 99 d8 [2] 9b d9 [2] 80 df [2] 9c d8 [2] 80 f7 }

  condition:
    any of them
}