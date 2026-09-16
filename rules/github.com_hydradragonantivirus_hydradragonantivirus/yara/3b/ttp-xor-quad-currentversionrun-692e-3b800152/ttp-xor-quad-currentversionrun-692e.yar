rule TTP_XOR_QUAD_CurrentVersionRun_692e {
  strings:
    $key_692e = { 3a 41 [2] 1e 4f [2] 35 63 [2] 1b 41 [2] 0f 5a [2] 00 40 [2] 1e 5d [2] 1c 5c [2] 07 5a [2] 1b 5d [2] 07 72 }

  condition:
    any of them
}