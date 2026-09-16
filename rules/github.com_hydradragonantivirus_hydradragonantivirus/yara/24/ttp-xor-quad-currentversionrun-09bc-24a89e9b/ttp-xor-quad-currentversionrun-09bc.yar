rule TTP_XOR_QUAD_CurrentVersionRun_09bc {
  strings:
    $key_09bc = { 5a d3 [2] 7e dd [2] 55 f1 [2] 7b d3 [2] 6f c8 [2] 60 d2 [2] 7e cf [2] 7c ce [2] 67 c8 [2] 7b cf [2] 67 e0 }

  condition:
    any of them
}