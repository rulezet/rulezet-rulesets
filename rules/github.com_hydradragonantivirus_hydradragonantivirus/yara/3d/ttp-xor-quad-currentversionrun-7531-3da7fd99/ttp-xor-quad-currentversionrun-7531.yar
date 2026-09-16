rule TTP_XOR_QUAD_CurrentVersionRun_7531 {
  strings:
    $key_7531 = { 26 5e [2] 02 50 [2] 29 7c [2] 07 5e [2] 13 45 [2] 1c 5f [2] 02 42 [2] 00 43 [2] 1b 45 [2] 07 42 [2] 1b 6d }

  condition:
    any of them
}