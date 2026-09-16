rule TTP_XOR_QUAD_CurrentVersionRun_085e {
  strings:
    $key_085e = { 5b 31 [2] 7f 3f [2] 54 13 [2] 7a 31 [2] 6e 2a [2] 61 30 [2] 7f 2d [2] 7d 2c [2] 66 2a [2] 7a 2d [2] 66 02 }

  condition:
    any of them
}