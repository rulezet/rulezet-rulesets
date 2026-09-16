rule TTP_XOR_QUAD_CurrentVersionRun_2841 {
  strings:
    $key_2841 = { 7b 2e [2] 5f 20 [2] 74 0c [2] 5a 2e [2] 4e 35 [2] 41 2f [2] 5f 32 [2] 5d 33 [2] 46 35 [2] 5a 32 [2] 46 1d }

  condition:
    any of them
}