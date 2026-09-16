rule TTP_XOR_QUAD_CurrentVersionRun_575d {
  strings:
    $key_575d = { 04 32 [2] 20 3c [2] 0b 10 [2] 25 32 [2] 31 29 [2] 3e 33 [2] 20 2e [2] 22 2f [2] 39 29 [2] 25 2e [2] 39 01 }

  condition:
    any of them
}