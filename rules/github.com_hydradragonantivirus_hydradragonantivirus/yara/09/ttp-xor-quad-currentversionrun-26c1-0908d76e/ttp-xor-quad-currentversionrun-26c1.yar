rule TTP_XOR_QUAD_CurrentVersionRun_26c1 {
  strings:
    $key_26c1 = { 75 ae [2] 51 a0 [2] 7a 8c [2] 54 ae [2] 40 b5 [2] 4f af [2] 51 b2 [2] 53 b3 [2] 48 b5 [2] 54 b2 [2] 48 9d }

  condition:
    any of them
}