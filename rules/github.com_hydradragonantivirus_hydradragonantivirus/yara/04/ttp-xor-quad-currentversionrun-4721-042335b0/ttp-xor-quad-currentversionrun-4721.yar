rule TTP_XOR_QUAD_CurrentVersionRun_4721 {
  strings:
    $key_4721 = { 14 4e [2] 30 40 [2] 1b 6c [2] 35 4e [2] 21 55 [2] 2e 4f [2] 30 52 [2] 32 53 [2] 29 55 [2] 35 52 [2] 29 7d }

  condition:
    any of them
}