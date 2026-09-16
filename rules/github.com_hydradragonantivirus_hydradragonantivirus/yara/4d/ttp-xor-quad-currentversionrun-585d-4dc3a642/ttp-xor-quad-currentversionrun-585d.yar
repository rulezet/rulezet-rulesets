rule TTP_XOR_QUAD_CurrentVersionRun_585d {
  strings:
    $key_585d = { 0b 32 [2] 2f 3c [2] 04 10 [2] 2a 32 [2] 3e 29 [2] 31 33 [2] 2f 2e [2] 2d 2f [2] 36 29 [2] 2a 2e [2] 36 01 }

  condition:
    any of them
}