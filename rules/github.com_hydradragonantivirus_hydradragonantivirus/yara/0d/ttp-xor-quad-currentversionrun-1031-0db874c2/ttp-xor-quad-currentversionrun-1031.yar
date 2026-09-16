rule TTP_XOR_QUAD_CurrentVersionRun_1031 {
  strings:
    $key_1031 = { 43 5e [2] 67 50 [2] 4c 7c [2] 62 5e [2] 76 45 [2] 79 5f [2] 67 42 [2] 65 43 [2] 7e 45 [2] 62 42 [2] 7e 6d }

  condition:
    any of them
}