rule TTP_XOR_QUAD_CurrentVersionRun_39b1 {
  strings:
    $key_39b1 = { 6a de [2] 4e d0 [2] 65 fc [2] 4b de [2] 5f c5 [2] 50 df [2] 4e c2 [2] 4c c3 [2] 57 c5 [2] 4b c2 [2] 57 ed }

  condition:
    any of them
}