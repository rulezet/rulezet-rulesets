rule TTP_XOR_QUAD_CurrentVersionRun_555d {
  strings:
    $key_555d = { 06 32 [2] 22 3c [2] 09 10 [2] 27 32 [2] 33 29 [2] 3c 33 [2] 22 2e [2] 20 2f [2] 3b 29 [2] 27 2e [2] 3b 01 }

  condition:
    any of them
}