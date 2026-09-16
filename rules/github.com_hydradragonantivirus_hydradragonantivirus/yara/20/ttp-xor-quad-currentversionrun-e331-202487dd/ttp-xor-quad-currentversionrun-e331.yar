rule TTP_XOR_QUAD_CurrentVersionRun_e331 {
  strings:
    $key_e331 = { b0 5e [2] 94 50 [2] bf 7c [2] 91 5e [2] 85 45 [2] 8a 5f [2] 94 42 [2] 96 43 [2] 8d 45 [2] 91 42 [2] 8d 6d }

  condition:
    any of them
}