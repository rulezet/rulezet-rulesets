rule TTP_XOR_QUAD_CurrentVersionRun_4d51 {
  strings:
    $key_4d51 = { 1e 3e [2] 3a 30 [2] 11 1c [2] 3f 3e [2] 2b 25 [2] 24 3f [2] 3a 22 [2] 38 23 [2] 23 25 [2] 3f 22 [2] 23 0d }

  condition:
    any of them
}