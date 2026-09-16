rule TTP_XOR_QUAD_CurrentVersionRun_18b1 {
  strings:
    $key_18b1 = { 4b de [2] 6f d0 [2] 44 fc [2] 6a de [2] 7e c5 [2] 71 df [2] 6f c2 [2] 6d c3 [2] 76 c5 [2] 6a c2 [2] 76 ed }

  condition:
    any of them
}