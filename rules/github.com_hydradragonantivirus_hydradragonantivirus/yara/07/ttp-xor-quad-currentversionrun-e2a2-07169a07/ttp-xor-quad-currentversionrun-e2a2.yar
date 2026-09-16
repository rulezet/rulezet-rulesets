rule TTP_XOR_QUAD_CurrentVersionRun_e2a2 {
  strings:
    $key_e2a2 = { b1 cd [2] 95 c3 [2] be ef [2] 90 cd [2] 84 d6 [2] 8b cc [2] 95 d1 [2] 97 d0 [2] 8c d6 [2] 90 d1 [2] 8c fe }

  condition:
    any of them
}