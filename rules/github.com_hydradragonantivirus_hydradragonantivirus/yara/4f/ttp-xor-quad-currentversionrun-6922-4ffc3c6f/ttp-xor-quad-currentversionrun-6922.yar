rule TTP_XOR_QUAD_CurrentVersionRun_6922 {
  strings:
    $key_6922 = { 3a 4d [2] 1e 43 [2] 35 6f [2] 1b 4d [2] 0f 56 [2] 00 4c [2] 1e 51 [2] 1c 50 [2] 07 56 [2] 1b 51 [2] 07 7e }

  condition:
    any of them
}