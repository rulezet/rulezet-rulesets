rule TTP_XOR_QUAD_CurrentVersionRun_6d0e {
  strings:
    $key_6d0e = { 3e 61 [2] 1a 6f [2] 31 43 [2] 1f 61 [2] 0b 7a [2] 04 60 [2] 1a 7d [2] 18 7c [2] 03 7a [2] 1f 7d [2] 03 52 }

  condition:
    any of them
}