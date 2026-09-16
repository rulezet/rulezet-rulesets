rule TTP_XOR_QUAD_CurrentVersionRun_02b2 {
  strings:
    $key_02b2 = { 51 dd [2] 75 d3 [2] 5e ff [2] 70 dd [2] 64 c6 [2] 6b dc [2] 75 c1 [2] 77 c0 [2] 6c c6 [2] 70 c1 [2] 6c ee }

  condition:
    any of them
}