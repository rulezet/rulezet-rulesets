rule TTP_XOR_QUAD_CurrentVersionRun_0a5e {
  strings:
    $key_0a5e = { 59 31 [2] 7d 3f [2] 56 13 [2] 78 31 [2] 6c 2a [2] 63 30 [2] 7d 2d [2] 7f 2c [2] 64 2a [2] 78 2d [2] 64 02 }

  condition:
    any of them
}