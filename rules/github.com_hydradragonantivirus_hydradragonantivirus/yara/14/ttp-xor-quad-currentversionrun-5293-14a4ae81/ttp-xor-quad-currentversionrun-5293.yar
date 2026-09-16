rule TTP_XOR_QUAD_CurrentVersionRun_5293 {
  strings:
    $key_5293 = { 01 fc [2] 25 f2 [2] 0e de [2] 20 fc [2] 34 e7 [2] 3b fd [2] 25 e0 [2] 27 e1 [2] 3c e7 [2] 20 e0 [2] 3c cf }

  condition:
    any of them
}