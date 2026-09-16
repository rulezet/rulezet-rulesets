rule TTP_XOR_QUAD_CurrentVersionRun_4c40 {
  strings:
    $key_4c40 = { 1f 2f [2] 3b 21 [2] 10 0d [2] 3e 2f [2] 2a 34 [2] 25 2e [2] 3b 33 [2] 39 32 [2] 22 34 [2] 3e 33 [2] 22 1c }

  condition:
    any of them
}