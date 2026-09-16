rule TTP_XOR_QUAD_CurrentVersionRun_09bd {
  strings:
    $key_09bd = { 5a d2 [2] 7e dc [2] 55 f0 [2] 7b d2 [2] 6f c9 [2] 60 d3 [2] 7e ce [2] 7c cf [2] 67 c9 [2] 7b ce [2] 67 e1 }

  condition:
    any of them
}