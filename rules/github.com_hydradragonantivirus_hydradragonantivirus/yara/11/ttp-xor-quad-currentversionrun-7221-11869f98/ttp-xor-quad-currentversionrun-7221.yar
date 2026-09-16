rule TTP_XOR_QUAD_CurrentVersionRun_7221 {
  strings:
    $key_7221 = { 21 4e [2] 05 40 [2] 2e 6c [2] 00 4e [2] 14 55 [2] 1b 4f [2] 05 52 [2] 07 53 [2] 1c 55 [2] 00 52 [2] 1c 7d }

  condition:
    any of them
}