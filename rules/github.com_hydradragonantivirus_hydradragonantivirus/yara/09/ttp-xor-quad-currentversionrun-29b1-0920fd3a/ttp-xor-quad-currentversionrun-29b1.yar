rule TTP_XOR_QUAD_CurrentVersionRun_29b1 {
  strings:
    $key_29b1 = { 7a de [2] 5e d0 [2] 75 fc [2] 5b de [2] 4f c5 [2] 40 df [2] 5e c2 [2] 5c c3 [2] 47 c5 [2] 5b c2 [2] 47 ed }

  condition:
    any of them
}