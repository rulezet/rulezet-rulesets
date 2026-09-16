rule TTP_XOR_QUAD_CurrentVersionRun_6e2e {
  strings:
    $key_6e2e = { 3d 41 [2] 19 4f [2] 32 63 [2] 1c 41 [2] 08 5a [2] 07 40 [2] 19 5d [2] 1b 5c [2] 00 5a [2] 1c 5d [2] 00 72 }

  condition:
    any of them
}