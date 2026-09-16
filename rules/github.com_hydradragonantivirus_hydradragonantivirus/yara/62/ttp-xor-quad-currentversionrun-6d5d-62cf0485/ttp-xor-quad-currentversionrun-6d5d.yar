rule TTP_XOR_QUAD_CurrentVersionRun_6d5d {
  strings:
    $key_6d5d = { 3e 32 [2] 1a 3c [2] 31 10 [2] 1f 32 [2] 0b 29 [2] 04 33 [2] 1a 2e [2] 18 2f [2] 03 29 [2] 1f 2e [2] 03 01 }

  condition:
    any of them
}