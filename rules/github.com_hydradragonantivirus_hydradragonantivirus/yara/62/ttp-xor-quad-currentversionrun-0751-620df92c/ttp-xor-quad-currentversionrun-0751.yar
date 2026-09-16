rule TTP_XOR_QUAD_CurrentVersionRun_0751 {
  strings:
    $key_0751 = { 54 3e [2] 70 30 [2] 5b 1c [2] 75 3e [2] 61 25 [2] 6e 3f [2] 70 22 [2] 72 23 [2] 69 25 [2] 75 22 [2] 69 0d }

  condition:
    any of them
}