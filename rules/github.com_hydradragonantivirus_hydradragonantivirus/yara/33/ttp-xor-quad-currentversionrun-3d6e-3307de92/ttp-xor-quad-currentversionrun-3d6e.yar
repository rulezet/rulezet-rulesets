rule TTP_XOR_QUAD_CurrentVersionRun_3d6e {
  strings:
    $key_3d6e = { 6e 01 [2] 4a 0f [2] 61 23 [2] 4f 01 [2] 5b 1a [2] 54 00 [2] 4a 1d [2] 48 1c [2] 53 1a [2] 4f 1d [2] 53 32 }

  condition:
    any of them
}