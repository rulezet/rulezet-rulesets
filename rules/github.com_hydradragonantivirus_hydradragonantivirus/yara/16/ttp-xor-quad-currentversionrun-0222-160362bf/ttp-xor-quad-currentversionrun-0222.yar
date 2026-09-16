rule TTP_XOR_QUAD_CurrentVersionRun_0222 {
  strings:
    $key_0222 = { 51 4d [2] 75 43 [2] 5e 6f [2] 70 4d [2] 64 56 [2] 6b 4c [2] 75 51 [2] 77 50 [2] 6c 56 [2] 70 51 [2] 6c 7e }

  condition:
    any of them
}