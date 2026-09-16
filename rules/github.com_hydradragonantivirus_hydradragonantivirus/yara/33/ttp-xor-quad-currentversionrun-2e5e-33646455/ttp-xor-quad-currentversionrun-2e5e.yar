rule TTP_XOR_QUAD_CurrentVersionRun_2e5e {
  strings:
    $key_2e5e = { 7d 31 [2] 59 3f [2] 72 13 [2] 5c 31 [2] 48 2a [2] 47 30 [2] 59 2d [2] 5b 2c [2] 40 2a [2] 5c 2d [2] 40 02 }

  condition:
    any of them
}