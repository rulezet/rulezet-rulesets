rule TTP_XOR_QUAD_CurrentVersionRun_727e {
  strings:
    $key_727e = { 21 11 [2] 05 1f [2] 2e 33 [2] 00 11 [2] 14 0a [2] 1b 10 [2] 05 0d [2] 07 0c [2] 1c 0a [2] 00 0d [2] 1c 22 }

  condition:
    any of them
}