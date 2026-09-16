rule TTP_XOR_QUAD_CurrentVersionRun_286f {
  strings:
    $key_286f = { 7b 00 [2] 5f 0e [2] 74 22 [2] 5a 00 [2] 4e 1b [2] 41 01 [2] 5f 1c [2] 5d 1d [2] 46 1b [2] 5a 1c [2] 46 33 }

  condition:
    any of them
}