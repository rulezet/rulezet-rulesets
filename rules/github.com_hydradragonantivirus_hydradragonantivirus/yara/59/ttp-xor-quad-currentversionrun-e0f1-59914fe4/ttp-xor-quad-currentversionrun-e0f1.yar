rule TTP_XOR_QUAD_CurrentVersionRun_e0f1 {
  strings:
    $key_e0f1 = { b3 9e [2] 97 90 [2] bc bc [2] 92 9e [2] 86 85 [2] 89 9f [2] 97 82 [2] 95 83 [2] 8e 85 [2] 92 82 [2] 8e ad }

  condition:
    any of them
}