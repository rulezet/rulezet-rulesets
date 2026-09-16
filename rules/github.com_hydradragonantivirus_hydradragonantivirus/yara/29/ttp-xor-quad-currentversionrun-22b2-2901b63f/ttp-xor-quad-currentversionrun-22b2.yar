rule TTP_XOR_QUAD_CurrentVersionRun_22b2 {
  strings:
    $key_22b2 = { 71 dd [2] 55 d3 [2] 7e ff [2] 50 dd [2] 44 c6 [2] 4b dc [2] 55 c1 [2] 57 c0 [2] 4c c6 [2] 50 c1 [2] 4c ee }

  condition:
    any of them
}