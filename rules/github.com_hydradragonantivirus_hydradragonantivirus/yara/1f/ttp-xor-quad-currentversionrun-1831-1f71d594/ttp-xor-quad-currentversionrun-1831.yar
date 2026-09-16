rule TTP_XOR_QUAD_CurrentVersionRun_1831 {
  strings:
    $key_1831 = { 4b 5e [2] 6f 50 [2] 44 7c [2] 6a 5e [2] 7e 45 [2] 71 5f [2] 6f 42 [2] 6d 43 [2] 76 45 [2] 6a 42 [2] 76 6d }

  condition:
    any of them
}