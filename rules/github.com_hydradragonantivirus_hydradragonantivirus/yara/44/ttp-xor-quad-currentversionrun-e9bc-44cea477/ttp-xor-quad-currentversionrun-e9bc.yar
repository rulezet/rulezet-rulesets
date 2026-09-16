rule TTP_XOR_QUAD_CurrentVersionRun_e9bc {
  strings:
    $key_e9bc = { ba d3 [2] 9e dd [2] b5 f1 [2] 9b d3 [2] 8f c8 [2] 80 d2 [2] 9e cf [2] 9c ce [2] 87 c8 [2] 9b cf [2] 87 e0 }

  condition:
    any of them
}