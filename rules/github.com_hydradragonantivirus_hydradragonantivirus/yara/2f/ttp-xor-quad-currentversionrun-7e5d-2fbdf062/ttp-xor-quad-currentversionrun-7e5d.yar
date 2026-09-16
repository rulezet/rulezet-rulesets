rule TTP_XOR_QUAD_CurrentVersionRun_7e5d {
  strings:
    $key_7e5d = { 2d 32 [2] 09 3c [2] 22 10 [2] 0c 32 [2] 18 29 [2] 17 33 [2] 09 2e [2] 0b 2f [2] 10 29 [2] 0c 2e [2] 10 01 }

  condition:
    any of them
}