rule TTP_XOR_QUAD_CurrentVersionRun_2b22 {
  strings:
    $key_2b22 = { 78 4d [2] 5c 43 [2] 77 6f [2] 59 4d [2] 4d 56 [2] 42 4c [2] 5c 51 [2] 5e 50 [2] 45 56 [2] 59 51 [2] 45 7e }

  condition:
    any of them
}