rule TTP_XOR_QUAD_CurrentVersionRun_4c21 {
  strings:
    $key_4c21 = { 1f 4e [2] 3b 40 [2] 10 6c [2] 3e 4e [2] 2a 55 [2] 25 4f [2] 3b 52 [2] 39 53 [2] 22 55 [2] 3e 52 [2] 22 7d }

  condition:
    any of them
}