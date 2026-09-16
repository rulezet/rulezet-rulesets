rule TTP_XOR_QUAD_CurrentVersionRun_69b1 {
  strings:
    $key_69b1 = { 3a de [2] 1e d0 [2] 35 fc [2] 1b de [2] 0f c5 [2] 00 df [2] 1e c2 [2] 1c c3 [2] 07 c5 [2] 1b c2 [2] 07 ed }

  condition:
    any of them
}