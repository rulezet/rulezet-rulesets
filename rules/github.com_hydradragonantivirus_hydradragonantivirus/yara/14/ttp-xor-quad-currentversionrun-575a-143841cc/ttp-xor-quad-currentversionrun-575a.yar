rule TTP_XOR_QUAD_CurrentVersionRun_575a {
  strings:
    $key_575a = { 04 35 [2] 20 3b [2] 0b 17 [2] 25 35 [2] 31 2e [2] 3e 34 [2] 20 29 [2] 22 28 [2] 39 2e [2] 25 29 [2] 39 06 }

  condition:
    any of them
}