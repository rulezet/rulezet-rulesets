rule TTP_XOR_QUAD_CurrentVersionRun_3931 {
  strings:
    $key_3931 = { 6a 5e [2] 4e 50 [2] 65 7c [2] 4b 5e [2] 5f 45 [2] 50 5f [2] 4e 42 [2] 4c 43 [2] 57 45 [2] 4b 42 [2] 57 6d }

  condition:
    any of them
}