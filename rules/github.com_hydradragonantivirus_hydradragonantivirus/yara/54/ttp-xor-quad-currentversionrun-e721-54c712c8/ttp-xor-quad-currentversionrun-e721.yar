rule TTP_XOR_QUAD_CurrentVersionRun_e721 {
  strings:
    $key_e721 = { b4 4e [2] 90 40 [2] bb 6c [2] 95 4e [2] 81 55 [2] 8e 4f [2] 90 52 [2] 92 53 [2] 89 55 [2] 95 52 [2] 89 7d }

  condition:
    any of them
}