rule TTP_XOR_QUAD_CurrentVersionRun_f141 {
  strings:
    $key_f141 = { a2 2e [2] 86 20 [2] ad 0c [2] 83 2e [2] 97 35 [2] 98 2f [2] 86 32 [2] 84 33 [2] 9f 35 [2] 83 32 [2] 9f 1d }

  condition:
    any of them
}