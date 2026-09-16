rule TTP_XOR_QUAD_CurrentVersionRun_085a {
  strings:
    $key_085a = { 5b 35 [2] 7f 3b [2] 54 17 [2] 7a 35 [2] 6e 2e [2] 61 34 [2] 7f 29 [2] 7d 28 [2] 66 2e [2] 7a 29 [2] 66 06 }

  condition:
    any of them
}