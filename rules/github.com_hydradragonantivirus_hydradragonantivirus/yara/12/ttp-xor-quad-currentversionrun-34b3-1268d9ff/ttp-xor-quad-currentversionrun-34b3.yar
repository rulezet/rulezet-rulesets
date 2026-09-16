rule TTP_XOR_QUAD_CurrentVersionRun_34b3 {
  strings:
    $key_34b3 = { 67 dc [2] 43 d2 [2] 68 fe [2] 46 dc [2] 52 c7 [2] 5d dd [2] 43 c0 [2] 41 c1 [2] 5a c7 [2] 46 c0 [2] 5a ef }

  condition:
    any of them
}