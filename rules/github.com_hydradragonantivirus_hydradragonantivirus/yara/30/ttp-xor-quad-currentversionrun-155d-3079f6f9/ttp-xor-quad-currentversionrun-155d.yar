rule TTP_XOR_QUAD_CurrentVersionRun_155d {
  strings:
    $key_155d = { 46 32 [2] 62 3c [2] 49 10 [2] 67 32 [2] 73 29 [2] 7c 33 [2] 62 2e [2] 60 2f [2] 7b 29 [2] 67 2e [2] 7b 01 }

  condition:
    any of them
}