rule TTP_XOR_QUAD_CurrentVersionRun_185a {
  strings:
    $key_185a = { 4b 35 [2] 6f 3b [2] 44 17 [2] 6a 35 [2] 7e 2e [2] 71 34 [2] 6f 29 [2] 6d 28 [2] 76 2e [2] 6a 29 [2] 76 06 }

  condition:
    any of them
}