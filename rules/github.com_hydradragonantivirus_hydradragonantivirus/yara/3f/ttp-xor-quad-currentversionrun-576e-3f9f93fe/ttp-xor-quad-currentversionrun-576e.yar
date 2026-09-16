rule TTP_XOR_QUAD_CurrentVersionRun_576e {
  strings:
    $key_576e = { 04 01 [2] 20 0f [2] 0b 23 [2] 25 01 [2] 31 1a [2] 3e 00 [2] 20 1d [2] 22 1c [2] 39 1a [2] 25 1d [2] 39 32 }

  condition:
    any of them
}