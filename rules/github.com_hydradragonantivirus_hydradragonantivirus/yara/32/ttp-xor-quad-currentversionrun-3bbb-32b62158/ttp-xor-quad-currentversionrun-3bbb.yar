rule TTP_XOR_QUAD_CurrentVersionRun_3bbb {
  strings:
    $key_3bbb = { 68 d4 [2] 4c da [2] 67 f6 [2] 49 d4 [2] 5d cf [2] 52 d5 [2] 4c c8 [2] 4e c9 [2] 55 cf [2] 49 c8 [2] 55 e7 }

  condition:
    any of them
}