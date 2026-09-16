rule TTP_XOR_QUAD_CurrentVersionRun_727d {
  strings:
    $key_727d = { 21 12 [2] 05 1c [2] 2e 30 [2] 00 12 [2] 14 09 [2] 1b 13 [2] 05 0e [2] 07 0f [2] 1c 09 [2] 00 0e [2] 1c 21 }

  condition:
    any of them
}