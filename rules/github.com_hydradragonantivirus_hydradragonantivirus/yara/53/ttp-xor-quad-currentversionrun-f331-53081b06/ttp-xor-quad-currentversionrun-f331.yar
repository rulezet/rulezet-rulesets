rule TTP_XOR_QUAD_CurrentVersionRun_f331 {
  strings:
    $key_f331 = { a0 5e [2] 84 50 [2] af 7c [2] 81 5e [2] 95 45 [2] 9a 5f [2] 84 42 [2] 86 43 [2] 9d 45 [2] 81 42 [2] 9d 6d }

  condition:
    any of them
}