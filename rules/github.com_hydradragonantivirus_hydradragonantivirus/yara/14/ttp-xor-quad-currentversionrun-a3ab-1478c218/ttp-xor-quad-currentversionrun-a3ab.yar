rule TTP_XOR_QUAD_CurrentVersionRun_a3ab {
  strings:
    $key_a3ab = { f0 c4 [2] d4 ca [2] ff e6 [2] d1 c4 [2] c5 df [2] ca c5 [2] d4 d8 [2] d6 d9 [2] cd df [2] d1 d8 [2] cd f7 }

  condition:
    any of them
}