rule TTP_XOR_QUAD_CurrentVersionRun_3431 {
  strings:
    $key_3431 = { 67 5e [2] 43 50 [2] 68 7c [2] 46 5e [2] 52 45 [2] 5d 5f [2] 43 42 [2] 41 43 [2] 5a 45 [2] 46 42 [2] 5a 6d }

  condition:
    any of them
}