rule TTP_XOR_QUAD_CurrentVersionRun_fcb1 {
  strings:
    $key_fcb1 = { af de [2] 8b d0 [2] a0 fc [2] 8e de [2] 9a c5 [2] 95 df [2] 8b c2 [2] 89 c3 [2] 92 c5 [2] 8e c2 [2] 92 ed }

  condition:
    any of them
}