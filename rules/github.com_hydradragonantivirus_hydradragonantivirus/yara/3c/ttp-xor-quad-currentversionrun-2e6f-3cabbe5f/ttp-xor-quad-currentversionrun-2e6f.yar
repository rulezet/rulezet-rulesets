rule TTP_XOR_QUAD_CurrentVersionRun_2e6f {
  strings:
    $key_2e6f = { 7d 00 [2] 59 0e [2] 72 22 [2] 5c 00 [2] 48 1b [2] 47 01 [2] 59 1c [2] 5b 1d [2] 40 1b [2] 5c 1c [2] 40 33 }

  condition:
    any of them
}