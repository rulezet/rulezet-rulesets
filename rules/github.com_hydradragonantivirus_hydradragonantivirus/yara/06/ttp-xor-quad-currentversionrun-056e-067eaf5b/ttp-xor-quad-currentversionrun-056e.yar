rule TTP_XOR_QUAD_CurrentVersionRun_056e {
  strings:
    $key_056e = { 56 01 [2] 72 0f [2] 59 23 [2] 77 01 [2] 63 1a [2] 6c 00 [2] 72 1d [2] 70 1c [2] 6b 1a [2] 77 1d [2] 6b 32 }

  condition:
    any of them
}