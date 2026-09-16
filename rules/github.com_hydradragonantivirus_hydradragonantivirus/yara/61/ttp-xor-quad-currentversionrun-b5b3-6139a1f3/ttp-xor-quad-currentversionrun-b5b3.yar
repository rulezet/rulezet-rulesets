rule TTP_XOR_QUAD_CurrentVersionRun_b5b3 {
  strings:
    $key_b5b3 = { e6 dc [2] c2 d2 [2] e9 fe [2] c7 dc [2] d3 c7 [2] dc dd [2] c2 c0 [2] c0 c1 [2] db c7 [2] c7 c0 [2] db ef }

  condition:
    any of them
}