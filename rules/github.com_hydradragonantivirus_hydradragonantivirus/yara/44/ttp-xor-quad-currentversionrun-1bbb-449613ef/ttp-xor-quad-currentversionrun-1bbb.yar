rule TTP_XOR_QUAD_CurrentVersionRun_1bbb {
  strings:
    $key_1bbb = { 48 d4 [2] 6c da [2] 47 f6 [2] 69 d4 [2] 7d cf [2] 72 d5 [2] 6c c8 [2] 6e c9 [2] 75 cf [2] 69 c8 [2] 75 e7 }

  condition:
    any of them
}