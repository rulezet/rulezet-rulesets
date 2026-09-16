rule TTP_XOR_QUAD_CurrentVersionRun_6751 {
  strings:
    $key_6751 = { 34 3e [2] 10 30 [2] 3b 1c [2] 15 3e [2] 01 25 [2] 0e 3f [2] 10 22 [2] 12 23 [2] 09 25 [2] 15 22 [2] 09 0d }

  condition:
    any of them
}