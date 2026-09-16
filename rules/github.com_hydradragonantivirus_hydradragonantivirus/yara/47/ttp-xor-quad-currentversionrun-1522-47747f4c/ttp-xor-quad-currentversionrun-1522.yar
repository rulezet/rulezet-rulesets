rule TTP_XOR_QUAD_CurrentVersionRun_1522 {
  strings:
    $key_1522 = { 46 4d [2] 62 43 [2] 49 6f [2] 67 4d [2] 73 56 [2] 7c 4c [2] 62 51 [2] 60 50 [2] 7b 56 [2] 67 51 [2] 7b 7e }

  condition:
    any of them
}