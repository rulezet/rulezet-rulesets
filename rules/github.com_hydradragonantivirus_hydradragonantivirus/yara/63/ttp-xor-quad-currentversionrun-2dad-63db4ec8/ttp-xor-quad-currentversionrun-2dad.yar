rule TTP_XOR_QUAD_CurrentVersionRun_2dad {
  strings:
    $key_2dad = { 7e c2 [2] 5a cc [2] 71 e0 [2] 5f c2 [2] 4b d9 [2] 44 c3 [2] 5a de [2] 58 df [2] 43 d9 [2] 5f de [2] 43 f1 }

  condition:
    any of them
}