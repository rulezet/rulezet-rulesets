rule TTP_XOR_QUAD_CurrentVersionRun_386e {
  strings:
    $key_386e = { 6b 01 [2] 4f 0f [2] 64 23 [2] 4a 01 [2] 5e 1a [2] 51 00 [2] 4f 1d [2] 4d 1c [2] 56 1a [2] 4a 1d [2] 56 32 }

  condition:
    any of them
}