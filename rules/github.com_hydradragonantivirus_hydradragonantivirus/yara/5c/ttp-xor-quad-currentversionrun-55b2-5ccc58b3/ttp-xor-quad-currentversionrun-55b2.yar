rule TTP_XOR_QUAD_CurrentVersionRun_55b2 {
  strings:
    $key_55b2 = { 06 dd [2] 22 d3 [2] 09 ff [2] 27 dd [2] 33 c6 [2] 3c dc [2] 22 c1 [2] 20 c0 [2] 3b c6 [2] 27 c1 [2] 3b ee }

  condition:
    any of them
}