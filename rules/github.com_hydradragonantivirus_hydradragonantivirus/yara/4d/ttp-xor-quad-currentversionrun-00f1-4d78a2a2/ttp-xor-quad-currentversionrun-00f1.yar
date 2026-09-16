rule TTP_XOR_QUAD_CurrentVersionRun_00f1 {
  strings:
    $key_00f1 = { 53 9e [2] 77 90 [2] 5c bc [2] 72 9e [2] 66 85 [2] 69 9f [2] 77 82 [2] 75 83 [2] 6e 85 [2] 72 82 [2] 6e ad }

  condition:
    any of them
}