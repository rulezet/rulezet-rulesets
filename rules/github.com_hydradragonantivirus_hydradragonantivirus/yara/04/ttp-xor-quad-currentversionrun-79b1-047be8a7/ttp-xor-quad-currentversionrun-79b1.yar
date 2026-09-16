rule TTP_XOR_QUAD_CurrentVersionRun_79b1 {
  strings:
    $key_79b1 = { 2a de [2] 0e d0 [2] 25 fc [2] 0b de [2] 1f c5 [2] 10 df [2] 0e c2 [2] 0c c3 [2] 17 c5 [2] 0b c2 [2] 17 ed }

  condition:
    any of them
}