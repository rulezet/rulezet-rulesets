rule TTP_XOR_QUAD_CurrentVersionRun_7551 {
  strings:
    $key_7551 = { 26 3e [2] 02 30 [2] 29 1c [2] 07 3e [2] 13 25 [2] 1c 3f [2] 02 22 [2] 00 23 [2] 1b 25 [2] 07 22 [2] 1b 0d }

  condition:
    any of them
}