rule TTP_XOR_QUAD_CurrentVersionRun_e9b1 {
  strings:
    $key_e9b1 = { ba de [2] 9e d0 [2] b5 fc [2] 9b de [2] 8f c5 [2] 80 df [2] 9e c2 [2] 9c c3 [2] 87 c5 [2] 9b c2 [2] 87 ed }

  condition:
    any of them
}