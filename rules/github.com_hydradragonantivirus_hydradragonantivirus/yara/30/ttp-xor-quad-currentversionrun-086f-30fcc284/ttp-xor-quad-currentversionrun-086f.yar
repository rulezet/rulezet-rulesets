rule TTP_XOR_QUAD_CurrentVersionRun_086f {
  strings:
    $key_086f = { 5b 00 [2] 7f 0e [2] 54 22 [2] 7a 00 [2] 6e 1b [2] 61 01 [2] 7f 1c [2] 7d 1d [2] 66 1b [2] 7a 1c [2] 66 33 }

  condition:
    any of them
}