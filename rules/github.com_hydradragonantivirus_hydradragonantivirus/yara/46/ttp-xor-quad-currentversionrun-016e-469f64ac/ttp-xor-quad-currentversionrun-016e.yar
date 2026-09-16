rule TTP_XOR_QUAD_CurrentVersionRun_016e {
  strings:
    $key_016e = { 52 01 [2] 76 0f [2] 5d 23 [2] 73 01 [2] 67 1a [2] 68 00 [2] 76 1d [2] 74 1c [2] 6f 1a [2] 73 1d [2] 6f 32 }

  condition:
    any of them
}