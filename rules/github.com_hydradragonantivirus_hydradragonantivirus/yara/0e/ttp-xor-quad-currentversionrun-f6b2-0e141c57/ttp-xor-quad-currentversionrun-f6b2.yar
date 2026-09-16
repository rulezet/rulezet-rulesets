rule TTP_XOR_QUAD_CurrentVersionRun_f6b2 {
  strings:
    $key_f6b2 = { a5 dd [2] 81 d3 [2] aa ff [2] 84 dd [2] 90 c6 [2] 9f dc [2] 81 c1 [2] 83 c0 [2] 98 c6 [2] 84 c1 [2] 98 ee }

  condition:
    any of them
}