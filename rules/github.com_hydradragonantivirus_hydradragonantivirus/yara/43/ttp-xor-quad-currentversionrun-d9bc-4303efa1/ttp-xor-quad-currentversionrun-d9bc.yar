rule TTP_XOR_QUAD_CurrentVersionRun_d9bc {
  strings:
    $key_d9bc = { 8a d3 [2] ae dd [2] 85 f1 [2] ab d3 [2] bf c8 [2] b0 d2 [2] ae cf [2] ac ce [2] b7 c8 [2] ab cf [2] b7 e0 }

  condition:
    any of them
}