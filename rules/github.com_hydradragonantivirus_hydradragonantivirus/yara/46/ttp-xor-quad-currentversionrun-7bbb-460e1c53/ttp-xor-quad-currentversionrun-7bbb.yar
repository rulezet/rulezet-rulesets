rule TTP_XOR_QUAD_CurrentVersionRun_7bbb {
  strings:
    $key_7bbb = { 28 d4 [2] 0c da [2] 27 f6 [2] 09 d4 [2] 1d cf [2] 12 d5 [2] 0c c8 [2] 0e c9 [2] 15 cf [2] 09 c8 [2] 15 e7 }

  condition:
    any of them
}