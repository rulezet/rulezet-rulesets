rule TTP_XOR_QUAD_CurrentVersionRun_4522 {
  strings:
    $key_4522 = { 16 4d [2] 32 43 [2] 19 6f [2] 37 4d [2] 23 56 [2] 2c 4c [2] 32 51 [2] 30 50 [2] 2b 56 [2] 37 51 [2] 2b 7e }

  condition:
    any of them
}