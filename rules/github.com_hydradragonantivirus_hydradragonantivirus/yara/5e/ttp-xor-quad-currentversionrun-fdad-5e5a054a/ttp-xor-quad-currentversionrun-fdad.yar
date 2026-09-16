rule TTP_XOR_QUAD_CurrentVersionRun_fdad {
  strings:
    $key_fdad = { ae c2 [2] 8a cc [2] a1 e0 [2] 8f c2 [2] 9b d9 [2] 94 c3 [2] 8a de [2] 88 df [2] 93 d9 [2] 8f de [2] 93 f1 }

  condition:
    any of them
}