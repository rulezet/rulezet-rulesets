rule TTP_XOR_QUAD_CurrentVersionRun_f0f1 {
  strings:
    $key_f0f1 = { a3 9e [2] 87 90 [2] ac bc [2] 82 9e [2] 96 85 [2] 99 9f [2] 87 82 [2] 85 83 [2] 9e 85 [2] 82 82 [2] 9e ad }

  condition:
    any of them
}