rule TTP_XOR_QUAD_CurrentVersionRun_2e22 {
  strings:
    $key_2e22 = { 7d 4d [2] 59 43 [2] 72 6f [2] 5c 4d [2] 48 56 [2] 47 4c [2] 59 51 [2] 5b 50 [2] 40 56 [2] 5c 51 [2] 40 7e }

  condition:
    any of them
}