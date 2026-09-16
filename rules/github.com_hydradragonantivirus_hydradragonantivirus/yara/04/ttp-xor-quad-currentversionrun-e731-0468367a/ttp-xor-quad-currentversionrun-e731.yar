rule TTP_XOR_QUAD_CurrentVersionRun_e731 {
  strings:
    $key_e731 = { b4 5e [2] 90 50 [2] bb 7c [2] 95 5e [2] 81 45 [2] 8e 5f [2] 90 42 [2] 92 43 [2] 89 45 [2] 95 42 [2] 89 6d }

  condition:
    any of them
}