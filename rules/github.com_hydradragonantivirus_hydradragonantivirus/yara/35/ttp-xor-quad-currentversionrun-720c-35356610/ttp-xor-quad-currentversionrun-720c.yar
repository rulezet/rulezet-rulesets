rule TTP_XOR_QUAD_CurrentVersionRun_720c {
  strings:
    $key_720c = { 21 63 [2] 05 6d [2] 2e 41 [2] 00 63 [2] 14 78 [2] 1b 62 [2] 05 7f [2] 07 7e [2] 1c 78 [2] 00 7f [2] 1c 50 }

  condition:
    any of them
}