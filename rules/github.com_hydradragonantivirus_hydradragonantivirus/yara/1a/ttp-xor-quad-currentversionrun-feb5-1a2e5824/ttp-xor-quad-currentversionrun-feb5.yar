rule TTP_XOR_QUAD_CurrentVersionRun_feb5 {
  strings:
    $key_feb5 = { ad da [2] 89 d4 [2] a2 f8 [2] 8c da [2] 98 c1 [2] 97 db [2] 89 c6 [2] 8b c7 [2] 90 c1 [2] 8c c6 [2] 90 e9 }

  condition:
    any of them
}