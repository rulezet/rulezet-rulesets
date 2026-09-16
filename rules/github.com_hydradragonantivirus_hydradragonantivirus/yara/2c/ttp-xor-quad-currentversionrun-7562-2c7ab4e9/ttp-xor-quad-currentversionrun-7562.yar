rule TTP_XOR_QUAD_CurrentVersionRun_7562 {
  strings:
    $key_7562 = { 26 0d [2] 02 03 [2] 29 2f [2] 07 0d [2] 13 16 [2] 1c 0c [2] 02 11 [2] 00 10 [2] 1b 16 [2] 07 11 [2] 1b 3e }

  condition:
    any of them
}