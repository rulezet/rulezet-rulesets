rule TTP_XOR_QUAD_CurrentVersionRun_3b31 {
  strings:
    $key_3b31 = { 68 5e [2] 4c 50 [2] 67 7c [2] 49 5e [2] 5d 45 [2] 52 5f [2] 4c 42 [2] 4e 43 [2] 55 45 [2] 49 42 [2] 55 6d }

  condition:
    any of them
}