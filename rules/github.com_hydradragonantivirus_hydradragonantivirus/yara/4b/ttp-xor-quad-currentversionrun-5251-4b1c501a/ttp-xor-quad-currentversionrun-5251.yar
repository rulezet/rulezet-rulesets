rule TTP_XOR_QUAD_CurrentVersionRun_5251 {
  strings:
    $key_5251 = { 01 3e [2] 25 30 [2] 0e 1c [2] 20 3e [2] 34 25 [2] 3b 3f [2] 25 22 [2] 27 23 [2] 3c 25 [2] 20 22 [2] 3c 0d }

  condition:
    any of them
}