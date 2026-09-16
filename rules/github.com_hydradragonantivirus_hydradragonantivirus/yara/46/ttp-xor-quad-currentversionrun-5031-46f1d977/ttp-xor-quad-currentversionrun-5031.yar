rule TTP_XOR_QUAD_CurrentVersionRun_5031 {
  strings:
    $key_5031 = { 03 5e [2] 27 50 [2] 0c 7c [2] 22 5e [2] 36 45 [2] 39 5f [2] 27 42 [2] 25 43 [2] 3e 45 [2] 22 42 [2] 3e 6d }

  condition:
    any of them
}