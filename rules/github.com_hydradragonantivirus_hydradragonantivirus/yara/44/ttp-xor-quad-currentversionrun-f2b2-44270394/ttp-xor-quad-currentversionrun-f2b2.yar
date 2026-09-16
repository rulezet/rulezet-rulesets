rule TTP_XOR_QUAD_CurrentVersionRun_f2b2 {
  strings:
    $key_f2b2 = { a1 dd [2] 85 d3 [2] ae ff [2] 80 dd [2] 94 c6 [2] 9b dc [2] 85 c1 [2] 87 c0 [2] 9c c6 [2] 80 c1 [2] 9c ee }

  condition:
    any of them
}