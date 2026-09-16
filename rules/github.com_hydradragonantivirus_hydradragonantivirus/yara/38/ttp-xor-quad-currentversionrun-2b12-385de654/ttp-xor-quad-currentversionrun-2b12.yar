rule TTP_XOR_QUAD_CurrentVersionRun_2b12 {
  strings:
    $key_2b12 = { 78 7d [2] 5c 73 [2] 77 5f [2] 59 7d [2] 4d 66 [2] 42 7c [2] 5c 61 [2] 5e 60 [2] 45 66 [2] 59 61 [2] 45 4e }

  condition:
    any of them
}