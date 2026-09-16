rule TTP_XOR_QUAD_CurrentVersionRun_febb {
  strings:
    $key_febb = { ad d4 [2] 89 da [2] a2 f6 [2] 8c d4 [2] 98 cf [2] 97 d5 [2] 89 c8 [2] 8b c9 [2] 90 cf [2] 8c c8 [2] 90 e7 }

  condition:
    any of them
}