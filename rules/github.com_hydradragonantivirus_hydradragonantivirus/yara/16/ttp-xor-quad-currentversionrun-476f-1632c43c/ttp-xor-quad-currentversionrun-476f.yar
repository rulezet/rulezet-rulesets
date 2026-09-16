rule TTP_XOR_QUAD_CurrentVersionRun_476f {
  strings:
    $key_476f = { 14 00 [2] 30 0e [2] 1b 22 [2] 35 00 [2] 21 1b [2] 2e 01 [2] 30 1c [2] 32 1d [2] 29 1b [2] 35 1c [2] 29 33 }

  condition:
    any of them
}