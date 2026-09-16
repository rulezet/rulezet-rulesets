rule TTP_XOR_QUAD_CurrentVersionRun_771e {
  strings:
    $key_771e = { 24 71 [2] 00 7f [2] 2b 53 [2] 05 71 [2] 11 6a [2] 1e 70 [2] 00 6d [2] 02 6c [2] 19 6a [2] 05 6d [2] 19 42 }

  condition:
    any of them
}