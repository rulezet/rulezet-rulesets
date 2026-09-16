rule TTP_XOR_QUAD_CurrentVersionRun_4b5a {
  strings:
    $key_4b5a = { 18 35 [2] 3c 3b [2] 17 17 [2] 39 35 [2] 2d 2e [2] 22 34 [2] 3c 29 [2] 3e 28 [2] 25 2e [2] 39 29 [2] 25 06 }

  condition:
    any of them
}