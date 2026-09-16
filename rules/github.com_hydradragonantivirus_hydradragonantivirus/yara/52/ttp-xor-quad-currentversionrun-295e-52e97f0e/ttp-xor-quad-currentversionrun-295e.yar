rule TTP_XOR_QUAD_CurrentVersionRun_295e {
  strings:
    $key_295e = { 7a 31 [2] 5e 3f [2] 75 13 [2] 5b 31 [2] 4f 2a [2] 40 30 [2] 5e 2d [2] 5c 2c [2] 47 2a [2] 5b 2d [2] 47 02 }

  condition:
    any of them
}