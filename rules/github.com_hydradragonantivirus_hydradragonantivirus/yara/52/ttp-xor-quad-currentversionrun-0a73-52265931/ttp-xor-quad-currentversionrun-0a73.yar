rule TTP_XOR_QUAD_CurrentVersionRun_0a73 {
  strings:
    $key_0a73 = { 59 1c [2] 7d 12 [2] 56 3e [2] 78 1c [2] 6c 07 [2] 63 1d [2] 7d 00 [2] 7f 01 [2] 64 07 [2] 78 00 [2] 64 2f }

  condition:
    any of them
}