rule TTP_XOR_QUAD_CurrentVersionRun_f9bd {
  strings:
    $key_f9bd = { aa d2 [2] 8e dc [2] a5 f0 [2] 8b d2 [2] 9f c9 [2] 90 d3 [2] 8e ce [2] 8c cf [2] 97 c9 [2] 8b ce [2] 97 e1 }

  condition:
    any of them
}