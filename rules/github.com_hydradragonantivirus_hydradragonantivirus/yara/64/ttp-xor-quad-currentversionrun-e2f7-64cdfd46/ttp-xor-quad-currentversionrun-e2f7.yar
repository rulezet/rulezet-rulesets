rule TTP_XOR_QUAD_CurrentVersionRun_e2f7 {
  strings:
    $key_e2f7 = { b1 98 [2] 95 96 [2] be ba [2] 90 98 [2] 84 83 [2] 8b 99 [2] 95 84 [2] 97 85 [2] 8c 83 [2] 90 84 [2] 8c ab }

  condition:
    any of them
}