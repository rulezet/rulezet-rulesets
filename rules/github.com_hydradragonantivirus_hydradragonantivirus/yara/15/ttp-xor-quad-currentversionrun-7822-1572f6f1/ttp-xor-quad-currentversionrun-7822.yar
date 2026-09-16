rule TTP_XOR_QUAD_CurrentVersionRun_7822 {
  strings:
    $key_7822 = { 2b 4d [2] 0f 43 [2] 24 6f [2] 0a 4d [2] 1e 56 [2] 11 4c [2] 0f 51 [2] 0d 50 [2] 16 56 [2] 0a 51 [2] 16 7e }

  condition:
    any of them
}