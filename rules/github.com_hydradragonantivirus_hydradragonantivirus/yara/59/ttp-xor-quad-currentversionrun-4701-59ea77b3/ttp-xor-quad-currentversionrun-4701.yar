rule TTP_XOR_QUAD_CurrentVersionRun_4701 {
  strings:
    $key_4701 = { 14 6e [2] 30 60 [2] 1b 4c [2] 35 6e [2] 21 75 [2] 2e 6f [2] 30 72 [2] 32 73 [2] 29 75 [2] 35 72 [2] 29 5d }

  condition:
    any of them
}