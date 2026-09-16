rule TTP_XOR_QUAD_CurrentVersionRun_2231 {
  strings:
    $key_2231 = { 71 5e [2] 55 50 [2] 7e 7c [2] 50 5e [2] 44 45 [2] 4b 5f [2] 55 42 [2] 57 43 [2] 4c 45 [2] 50 42 [2] 4c 6d }

  condition:
    any of them
}