rule TTP_XOR_QUAD_CurrentVersionRun_2b6f {
  strings:
    $key_2b6f = { 78 00 [2] 5c 0e [2] 77 22 [2] 59 00 [2] 4d 1b [2] 42 01 [2] 5c 1c [2] 5e 1d [2] 45 1b [2] 59 1c [2] 45 33 }

  condition:
    any of them
}