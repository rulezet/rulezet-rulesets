rule TTP_XOR_QUAD_CurrentVersionRun_4622 {
  strings:
    $key_4622 = { 15 4d [2] 31 43 [2] 1a 6f [2] 34 4d [2] 20 56 [2] 2f 4c [2] 31 51 [2] 33 50 [2] 28 56 [2] 34 51 [2] 28 7e }

  condition:
    any of them
}