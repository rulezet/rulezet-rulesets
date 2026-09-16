rule TTP_XOR_QUAD_CurrentVersionRun_e572 {
  strings:
    $key_e572 = { b6 1d [2] 92 13 [2] b9 3f [2] 97 1d [2] 83 06 [2] 8c 1c [2] 92 01 [2] 90 00 [2] 8b 06 [2] 97 01 [2] 8b 2e }

  condition:
    any of them
}