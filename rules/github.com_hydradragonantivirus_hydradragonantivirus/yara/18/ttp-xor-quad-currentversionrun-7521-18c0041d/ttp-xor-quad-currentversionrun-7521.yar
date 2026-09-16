rule TTP_XOR_QUAD_CurrentVersionRun_7521 {
  strings:
    $key_7521 = { 26 4e [2] 02 40 [2] 29 6c [2] 07 4e [2] 13 55 [2] 1c 4f [2] 02 52 [2] 00 53 [2] 1b 55 [2] 07 52 [2] 1b 7d }

  condition:
    any of them
}