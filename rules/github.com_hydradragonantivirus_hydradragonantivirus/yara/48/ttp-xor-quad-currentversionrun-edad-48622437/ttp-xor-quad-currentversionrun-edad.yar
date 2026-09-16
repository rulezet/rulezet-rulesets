rule TTP_XOR_QUAD_CurrentVersionRun_edad {
  strings:
    $key_edad = { be c2 [2] 9a cc [2] b1 e0 [2] 9f c2 [2] 8b d9 [2] 84 c3 [2] 9a de [2] 98 df [2] 83 d9 [2] 9f de [2] 83 f1 }

  condition:
    any of them
}