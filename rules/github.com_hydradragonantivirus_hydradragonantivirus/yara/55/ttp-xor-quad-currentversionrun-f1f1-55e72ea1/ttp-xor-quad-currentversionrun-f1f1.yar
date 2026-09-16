rule TTP_XOR_QUAD_CurrentVersionRun_f1f1 {
  strings:
    $key_f1f1 = { a2 9e [2] 86 90 [2] ad bc [2] 83 9e [2] 97 85 [2] 98 9f [2] 86 82 [2] 84 83 [2] 9f 85 [2] 83 82 [2] 9f ad }

  condition:
    any of them
}