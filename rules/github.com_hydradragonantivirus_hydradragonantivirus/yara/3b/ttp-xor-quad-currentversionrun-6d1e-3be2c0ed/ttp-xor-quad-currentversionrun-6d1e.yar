rule TTP_XOR_QUAD_CurrentVersionRun_6d1e {
  strings:
    $key_6d1e = { 3e 71 [2] 1a 7f [2] 31 53 [2] 1f 71 [2] 0b 6a [2] 04 70 [2] 1a 6d [2] 18 6c [2] 03 6a [2] 1f 6d [2] 03 42 }

  condition:
    any of them
}