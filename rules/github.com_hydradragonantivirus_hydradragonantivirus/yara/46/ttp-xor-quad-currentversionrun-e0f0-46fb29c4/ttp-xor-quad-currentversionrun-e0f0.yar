rule TTP_XOR_QUAD_CurrentVersionRun_e0f0 {
  strings:
    $key_e0f0 = { b3 9f [2] 97 91 [2] bc bd [2] 92 9f [2] 86 84 [2] 89 9e [2] 97 83 [2] 95 82 [2] 8e 84 [2] 92 83 [2] 8e ac }

  condition:
    any of them
}