rule TTP_XOR_QUAD_CurrentVersionRun_215e {
  strings:
    $key_215e = { 72 31 [2] 56 3f [2] 7d 13 [2] 53 31 [2] 47 2a [2] 48 30 [2] 56 2d [2] 54 2c [2] 4f 2a [2] 53 2d [2] 4f 02 }

  condition:
    any of them
}