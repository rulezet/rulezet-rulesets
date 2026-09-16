rule TTP_XOR_QUAD_CurrentVersionRun_5641 {
  strings:
    $key_5641 = { 05 2e [2] 21 20 [2] 0a 0c [2] 24 2e [2] 30 35 [2] 3f 2f [2] 21 32 [2] 23 33 [2] 38 35 [2] 24 32 [2] 38 1d }

  condition:
    any of them
}