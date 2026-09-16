rule TTP_XOR_QUAD_CurrentVersionRun_3251 {
  strings:
    $key_3251 = { 61 3e [2] 45 30 [2] 6e 1c [2] 40 3e [2] 54 25 [2] 5b 3f [2] 45 22 [2] 47 23 [2] 5c 25 [2] 40 22 [2] 5c 0d }

  condition:
    any of them
}