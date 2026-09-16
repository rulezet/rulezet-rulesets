rule TTP_XOR_QUAD_CurrentVersionRun_59b1 {
  strings:
    $key_59b1 = { 0a de [2] 2e d0 [2] 05 fc [2] 2b de [2] 3f c5 [2] 30 df [2] 2e c2 [2] 2c c3 [2] 37 c5 [2] 2b c2 [2] 37 ed }

  condition:
    any of them
}