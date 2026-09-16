rule TTP_XOR_QUAD_CurrentVersionRun_325e {
  strings:
    $key_325e = { 61 31 [2] 45 3f [2] 6e 13 [2] 40 31 [2] 54 2a [2] 5b 30 [2] 45 2d [2] 47 2c [2] 5c 2a [2] 40 2d [2] 5c 02 }

  condition:
    any of them
}