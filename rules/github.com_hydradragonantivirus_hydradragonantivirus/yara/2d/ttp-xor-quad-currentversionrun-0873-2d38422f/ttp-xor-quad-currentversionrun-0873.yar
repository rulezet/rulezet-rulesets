rule TTP_XOR_QUAD_CurrentVersionRun_0873 {
  strings:
    $key_0873 = { 5b 1c [2] 7f 12 [2] 54 3e [2] 7a 1c [2] 6e 07 [2] 61 1d [2] 7f 00 [2] 7d 01 [2] 66 07 [2] 7a 00 [2] 66 2f }

  condition:
    any of them
}