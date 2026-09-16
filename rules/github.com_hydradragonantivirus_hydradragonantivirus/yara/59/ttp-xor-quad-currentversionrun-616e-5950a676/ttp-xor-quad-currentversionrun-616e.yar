rule TTP_XOR_QUAD_CurrentVersionRun_616e {
  strings:
    $key_616e = { 32 01 [2] 16 0f [2] 3d 23 [2] 13 01 [2] 07 1a [2] 08 00 [2] 16 1d [2] 14 1c [2] 0f 1a [2] 13 1d [2] 0f 32 }

  condition:
    any of them
}