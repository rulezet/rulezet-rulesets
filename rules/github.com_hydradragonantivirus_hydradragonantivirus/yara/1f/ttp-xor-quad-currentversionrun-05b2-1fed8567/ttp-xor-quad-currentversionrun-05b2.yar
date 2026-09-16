rule TTP_XOR_QUAD_CurrentVersionRun_05b2 {
  strings:
    $key_05b2 = { 56 dd [2] 72 d3 [2] 59 ff [2] 77 dd [2] 63 c6 [2] 6c dc [2] 72 c1 [2] 70 c0 [2] 6b c6 [2] 77 c1 [2] 6b ee }

  condition:
    any of them
}