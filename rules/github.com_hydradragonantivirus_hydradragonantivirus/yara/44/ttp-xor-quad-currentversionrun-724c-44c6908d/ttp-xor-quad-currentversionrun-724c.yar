rule TTP_XOR_QUAD_CurrentVersionRun_724c {
  strings:
    $key_724c = { 21 23 [2] 05 2d [2] 2e 01 [2] 00 23 [2] 14 38 [2] 1b 22 [2] 05 3f [2] 07 3e [2] 1c 38 [2] 00 3f [2] 1c 10 }

  condition:
    any of them
}