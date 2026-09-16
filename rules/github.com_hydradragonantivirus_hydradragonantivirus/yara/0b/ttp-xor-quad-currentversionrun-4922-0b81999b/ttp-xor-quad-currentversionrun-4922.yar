rule TTP_XOR_QUAD_CurrentVersionRun_4922 {
  strings:
    $key_4922 = { 1a 4d [2] 3e 43 [2] 15 6f [2] 3b 4d [2] 2f 56 [2] 20 4c [2] 3e 51 [2] 3c 50 [2] 27 56 [2] 3b 51 [2] 27 7e }

  condition:
    any of them
}