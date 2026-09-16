rule TTP_XOR_QUAD_CurrentVersionRun_09b1 {
  strings:
    $key_09b1 = { 5a de [2] 7e d0 [2] 55 fc [2] 7b de [2] 6f c5 [2] 60 df [2] 7e c2 [2] 7c c3 [2] 67 c5 [2] 7b c2 [2] 67 ed }

  condition:
    any of them
}