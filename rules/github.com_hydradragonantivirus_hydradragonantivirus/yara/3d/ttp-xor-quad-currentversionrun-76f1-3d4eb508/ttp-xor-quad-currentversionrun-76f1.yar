rule TTP_XOR_QUAD_CurrentVersionRun_76f1 {
  strings:
    $key_76f1 = { 25 9e [2] 01 90 [2] 2a bc [2] 04 9e [2] 10 85 [2] 1f 9f [2] 01 82 [2] 03 83 [2] 18 85 [2] 04 82 [2] 18 ad }

  condition:
    any of them
}