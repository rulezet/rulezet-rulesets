rule TTP_XOR_QUAD_CurrentVersionRun_725d {
  strings:
    $key_725d = { 21 32 [2] 05 3c [2] 2e 10 [2] 00 32 [2] 14 29 [2] 1b 33 [2] 05 2e [2] 07 2f [2] 1c 29 [2] 00 2e [2] 1c 01 }

  condition:
    any of them
}