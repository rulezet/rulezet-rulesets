rule TTP_XOR_QUAD_CurrentVersionRun_37b2 {
  strings:
    $key_37b2 = { 64 dd [2] 40 d3 [2] 6b ff [2] 45 dd [2] 51 c6 [2] 5e dc [2] 40 c1 [2] 42 c0 [2] 59 c6 [2] 45 c1 [2] 59 ee }

  condition:
    any of them
}