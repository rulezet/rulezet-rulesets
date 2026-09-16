rule TTP_XOR_QUAD_CurrentVersionRun_216e {
  strings:
    $key_216e = { 72 01 [2] 56 0f [2] 7d 23 [2] 53 01 [2] 47 1a [2] 48 00 [2] 56 1d [2] 54 1c [2] 4f 1a [2] 53 1d [2] 4f 32 }

  condition:
    any of them
}