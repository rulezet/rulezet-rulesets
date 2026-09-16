rule TTP_XOR_QUAD_CurrentVersionRun_d093 {
  strings:
    $key_d093 = { 83 fc [2] a7 f2 [2] 8c de [2] a2 fc [2] b6 e7 [2] b9 fd [2] a7 e0 [2] a5 e1 [2] be e7 [2] a2 e0 [2] be cf }

  condition:
    any of them
}