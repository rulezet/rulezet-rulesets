rule TTP_XOR_QUAD_CurrentVersionRun_185d {
  strings:
    $key_185d = { 4b 32 [2] 6f 3c [2] 44 10 [2] 6a 32 [2] 7e 29 [2] 71 33 [2] 6f 2e [2] 6d 2f [2] 76 29 [2] 6a 2e [2] 76 01 }

  condition:
    any of them
}