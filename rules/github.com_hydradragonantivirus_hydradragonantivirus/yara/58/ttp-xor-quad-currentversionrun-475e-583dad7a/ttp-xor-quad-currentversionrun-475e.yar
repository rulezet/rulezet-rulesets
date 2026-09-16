rule TTP_XOR_QUAD_CurrentVersionRun_475e {
  strings:
    $key_475e = { 14 31 [2] 30 3f [2] 1b 13 [2] 35 31 [2] 21 2a [2] 2e 30 [2] 30 2d [2] 32 2c [2] 29 2a [2] 35 2d [2] 29 02 }

  condition:
    any of them
}