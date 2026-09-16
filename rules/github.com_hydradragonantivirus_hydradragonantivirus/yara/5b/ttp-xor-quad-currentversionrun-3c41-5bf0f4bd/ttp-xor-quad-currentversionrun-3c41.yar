rule TTP_XOR_QUAD_CurrentVersionRun_3c41 {
  strings:
    $key_3c41 = { 6f 2e [2] 4b 20 [2] 60 0c [2] 4e 2e [2] 5a 35 [2] 55 2f [2] 4b 32 [2] 49 33 [2] 52 35 [2] 4e 32 [2] 52 1d }

  condition:
    any of them
}