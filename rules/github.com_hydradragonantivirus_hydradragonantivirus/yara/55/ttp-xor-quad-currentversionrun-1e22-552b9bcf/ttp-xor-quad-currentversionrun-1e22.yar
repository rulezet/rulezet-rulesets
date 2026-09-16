rule TTP_XOR_QUAD_CurrentVersionRun_1e22 {
  strings:
    $key_1e22 = { 4d 4d [2] 69 43 [2] 42 6f [2] 6c 4d [2] 78 56 [2] 77 4c [2] 69 51 [2] 6b 50 [2] 70 56 [2] 6c 51 [2] 70 7e }

  condition:
    any of them
}