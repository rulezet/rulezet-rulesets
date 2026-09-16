rule TTP_XOR_QUAD_CurrentVersionRun_fe31 {
  strings:
    $key_fe31 = { ad 5e [2] 89 50 [2] a2 7c [2] 8c 5e [2] 98 45 [2] 97 5f [2] 89 42 [2] 8b 43 [2] 90 45 [2] 8c 42 [2] 90 6d }

  condition:
    any of them
}