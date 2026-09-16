rule TTP_XOR_QUAD_CurrentVersionRun_495a {
  strings:
    $key_495a = { 1a 35 [2] 3e 3b [2] 15 17 [2] 3b 35 [2] 2f 2e [2] 20 34 [2] 3e 29 [2] 3c 28 [2] 27 2e [2] 3b 29 [2] 27 06 }

  condition:
    any of them
}