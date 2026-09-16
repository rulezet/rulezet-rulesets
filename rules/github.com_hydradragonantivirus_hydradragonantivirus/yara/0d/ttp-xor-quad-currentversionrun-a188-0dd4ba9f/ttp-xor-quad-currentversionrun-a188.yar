rule TTP_XOR_QUAD_CurrentVersionRun_a188 {
  strings:
    $key_a188 = { f2 e7 [2] d6 e9 [2] fd c5 [2] d3 e7 [2] c7 fc [2] c8 e6 [2] d6 fb [2] d4 fa [2] cf fc [2] d3 fb [2] cf d4 }

  condition:
    any of them
}