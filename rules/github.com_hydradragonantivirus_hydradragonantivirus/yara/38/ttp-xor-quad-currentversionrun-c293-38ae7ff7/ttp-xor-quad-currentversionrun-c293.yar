rule TTP_XOR_QUAD_CurrentVersionRun_c293 {
  strings:
    $key_c293 = { 91 fc [2] b5 f2 [2] 9e de [2] b0 fc [2] a4 e7 [2] ab fd [2] b5 e0 [2] b7 e1 [2] ac e7 [2] b0 e0 [2] ac cf }

  condition:
    any of them
}