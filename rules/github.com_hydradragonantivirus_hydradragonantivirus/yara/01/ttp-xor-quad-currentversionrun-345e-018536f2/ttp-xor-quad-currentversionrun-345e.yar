rule TTP_XOR_QUAD_CurrentVersionRun_345e {
  strings:
    $key_345e = { 67 31 [2] 43 3f [2] 68 13 [2] 46 31 [2] 52 2a [2] 5d 30 [2] 43 2d [2] 41 2c [2] 5a 2a [2] 46 2d [2] 5a 02 }

  condition:
    any of them
}