rule TTP_XOR_QUAD_CurrentVersionRun_5bb1 {
  strings:
    $key_5bb1 = { 08 de [2] 2c d0 [2] 07 fc [2] 29 de [2] 3d c5 [2] 32 df [2] 2c c2 [2] 2e c3 [2] 35 c5 [2] 29 c2 [2] 35 ed }

  condition:
    any of them
}