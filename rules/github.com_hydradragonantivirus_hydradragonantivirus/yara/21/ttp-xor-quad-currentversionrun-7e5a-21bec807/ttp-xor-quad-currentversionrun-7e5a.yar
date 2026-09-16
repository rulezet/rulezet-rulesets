rule TTP_XOR_QUAD_CurrentVersionRun_7e5a {
  strings:
    $key_7e5a = { 2d 35 [2] 09 3b [2] 22 17 [2] 0c 35 [2] 18 2e [2] 17 34 [2] 09 29 [2] 0b 28 [2] 10 2e [2] 0c 29 [2] 10 06 }

  condition:
    any of them
}