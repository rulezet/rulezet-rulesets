rule TTP_XOR_QUAD_CurrentVersionRun_2bbb {
  strings:
    $key_2bbb = { 78 d4 [2] 5c da [2] 77 f6 [2] 59 d4 [2] 4d cf [2] 42 d5 [2] 5c c8 [2] 5e c9 [2] 45 cf [2] 59 c8 [2] 45 e7 }

  condition:
    any of them
}