rule TTP_XOR_QUAD_CurrentVersionRun_0aab {
  strings:
    $key_0aab = { 59 c4 [2] 7d ca [2] 56 e6 [2] 78 c4 [2] 6c df [2] 63 c5 [2] 7d d8 [2] 7f d9 [2] 64 df [2] 78 d8 [2] 64 f7 }

  condition:
    any of them
}