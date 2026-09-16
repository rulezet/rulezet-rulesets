rule TTP_XOR_QUAD_CurrentVersionRun_3e31 {
  strings:
    $key_3e31 = { 6d 5e [2] 49 50 [2] 62 7c [2] 4c 5e [2] 58 45 [2] 57 5f [2] 49 42 [2] 4b 43 [2] 50 45 [2] 4c 42 [2] 50 6d }

  condition:
    any of them
}