rule TTP_XOR_QUAD_CurrentVersionRun_5687 {
  strings:
    $key_5687 = { 05 e8 [2] 21 e6 [2] 0a ca [2] 24 e8 [2] 30 f3 [2] 3f e9 [2] 21 f4 [2] 23 f5 [2] 38 f3 [2] 24 f4 [2] 38 db }

  condition:
    any of them
}