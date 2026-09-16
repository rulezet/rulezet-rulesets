rule TTP_XOR_QUAD_CurrentVersionRun_30f1 {
  strings:
    $key_30f1 = { 63 9e [2] 47 90 [2] 6c bc [2] 42 9e [2] 56 85 [2] 59 9f [2] 47 82 [2] 45 83 [2] 5e 85 [2] 42 82 [2] 5e ad }

  condition:
    any of them
}