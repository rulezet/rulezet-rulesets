rule TTP_XOR_QUAD_CurrentVersionRun_066f {
  strings:
    $key_066f = { 55 00 [2] 71 0e [2] 5a 22 [2] 74 00 [2] 60 1b [2] 6f 01 [2] 71 1c [2] 73 1d [2] 68 1b [2] 74 1c [2] 68 33 }

  condition:
    any of them
}