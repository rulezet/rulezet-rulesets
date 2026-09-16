rule TTP_XOR_QUAD_CurrentVersionRun_722f {
  strings:
    $key_722f = { 21 40 [2] 05 4e [2] 2e 62 [2] 00 40 [2] 14 5b [2] 1b 41 [2] 05 5c [2] 07 5d [2] 1c 5b [2] 00 5c [2] 1c 73 }

  condition:
    any of them
}