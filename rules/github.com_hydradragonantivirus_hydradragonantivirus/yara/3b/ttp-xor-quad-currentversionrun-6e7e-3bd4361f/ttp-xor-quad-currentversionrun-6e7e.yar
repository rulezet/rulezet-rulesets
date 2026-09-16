rule TTP_XOR_QUAD_CurrentVersionRun_6e7e {
  strings:
    $key_6e7e = { 3d 11 [2] 19 1f [2] 32 33 [2] 1c 11 [2] 08 0a [2] 07 10 [2] 19 0d [2] 1b 0c [2] 00 0a [2] 1c 0d [2] 00 22 }

  condition:
    any of them
}