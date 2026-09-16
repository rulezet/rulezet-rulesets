rule TTP_XOR_QUAD_CurrentVersionRun_52b2 {
  strings:
    $key_52b2 = { 01 dd [2] 25 d3 [2] 0e ff [2] 20 dd [2] 34 c6 [2] 3b dc [2] 25 c1 [2] 27 c0 [2] 3c c6 [2] 20 c1 [2] 3c ee }

  condition:
    any of them
}