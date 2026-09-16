rule TTP_XOR_QUAD_CurrentVersionRun_00d2 {
  strings:
    $key_00d2 = { 53 bd [2] 77 b3 [2] 5c 9f [2] 72 bd [2] 66 a6 [2] 69 bc [2] 77 a1 [2] 75 a0 [2] 6e a6 [2] 72 a1 [2] 6e 8e }

  condition:
    any of them
}