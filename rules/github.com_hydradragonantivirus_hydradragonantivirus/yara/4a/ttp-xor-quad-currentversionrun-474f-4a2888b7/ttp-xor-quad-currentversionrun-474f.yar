rule TTP_XOR_QUAD_CurrentVersionRun_474f {
  strings:
    $key_474f = { 14 20 [2] 30 2e [2] 1b 02 [2] 35 20 [2] 21 3b [2] 2e 21 [2] 30 3c [2] 32 3d [2] 29 3b [2] 35 3c [2] 29 13 }

  condition:
    any of them
}