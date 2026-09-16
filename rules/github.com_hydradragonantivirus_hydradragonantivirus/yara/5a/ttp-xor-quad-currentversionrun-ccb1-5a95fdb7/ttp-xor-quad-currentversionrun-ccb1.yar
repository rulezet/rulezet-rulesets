rule TTP_XOR_QUAD_CurrentVersionRun_ccb1 {
  strings:
    $key_ccb1 = { 9f de [2] bb d0 [2] 90 fc [2] be de [2] aa c5 [2] a5 df [2] bb c2 [2] b9 c3 [2] a2 c5 [2] be c2 [2] a2 ed }

  condition:
    any of them
}