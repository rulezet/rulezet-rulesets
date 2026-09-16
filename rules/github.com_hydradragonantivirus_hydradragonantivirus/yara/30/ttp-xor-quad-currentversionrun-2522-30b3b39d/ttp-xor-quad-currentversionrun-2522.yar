rule TTP_XOR_QUAD_CurrentVersionRun_2522 {
  strings:
    $key_2522 = { 76 4d [2] 52 43 [2] 79 6f [2] 57 4d [2] 43 56 [2] 4c 4c [2] 52 51 [2] 50 50 [2] 4b 56 [2] 57 51 [2] 4b 7e }

  condition:
    any of them
}