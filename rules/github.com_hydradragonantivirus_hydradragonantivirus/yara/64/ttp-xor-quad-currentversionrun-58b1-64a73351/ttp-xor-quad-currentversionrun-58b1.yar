rule TTP_XOR_QUAD_CurrentVersionRun_58b1 {
  strings:
    $key_58b1 = { 0b de [2] 2f d0 [2] 04 fc [2] 2a de [2] 3e c5 [2] 31 df [2] 2f c2 [2] 2d c3 [2] 36 c5 [2] 2a c2 [2] 36 ed }

  condition:
    any of them
}