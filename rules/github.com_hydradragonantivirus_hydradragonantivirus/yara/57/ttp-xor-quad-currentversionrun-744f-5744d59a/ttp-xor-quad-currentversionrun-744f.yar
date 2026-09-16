rule TTP_XOR_QUAD_CurrentVersionRun_744f {
  strings:
    $key_744f = { 27 20 [2] 03 2e [2] 28 02 [2] 06 20 [2] 12 3b [2] 1d 21 [2] 03 3c [2] 01 3d [2] 1a 3b [2] 06 3c [2] 1a 13 }

  condition:
    any of them
}