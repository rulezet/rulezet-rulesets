rule TTP_XOR_QUAD_CurrentVersionRun_351a {
  strings:
    $key_351a = { 66 75 [2] 42 7b [2] 69 57 [2] 47 75 [2] 53 6e [2] 5c 74 [2] 42 69 [2] 40 68 [2] 5b 6e [2] 47 69 [2] 5b 46 }

  condition:
    any of them
}