rule TTP_XOR_QUAD_CurrentVersionRun_45b2 {
  strings:
    $key_45b2 = { 16 dd [2] 32 d3 [2] 19 ff [2] 37 dd [2] 23 c6 [2] 2c dc [2] 32 c1 [2] 30 c0 [2] 2b c6 [2] 37 c1 [2] 2b ee }

  condition:
    any of them
}