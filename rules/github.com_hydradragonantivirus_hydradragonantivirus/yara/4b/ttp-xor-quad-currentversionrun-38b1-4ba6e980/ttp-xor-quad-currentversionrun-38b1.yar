rule TTP_XOR_QUAD_CurrentVersionRun_38b1 {
  strings:
    $key_38b1 = { 6b de [2] 4f d0 [2] 64 fc [2] 4a de [2] 5e c5 [2] 51 df [2] 4f c2 [2] 4d c3 [2] 56 c5 [2] 4a c2 [2] 56 ed }

  condition:
    any of them
}