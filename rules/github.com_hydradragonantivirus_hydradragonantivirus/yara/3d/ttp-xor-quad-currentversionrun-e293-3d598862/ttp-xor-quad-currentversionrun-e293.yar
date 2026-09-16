rule TTP_XOR_QUAD_CurrentVersionRun_e293 {
  strings:
    $key_e293 = { b1 fc [2] 95 f2 [2] be de [2] 90 fc [2] 84 e7 [2] 8b fd [2] 95 e0 [2] 97 e1 [2] 8c e7 [2] 90 e0 [2] 8c cf }

  condition:
    any of them
}