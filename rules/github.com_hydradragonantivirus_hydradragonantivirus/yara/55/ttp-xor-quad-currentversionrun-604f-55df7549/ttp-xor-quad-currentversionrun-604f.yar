rule TTP_XOR_QUAD_CurrentVersionRun_604f {
  strings:
    $key_604f = { 33 20 [2] 17 2e [2] 3c 02 [2] 12 20 [2] 06 3b [2] 09 21 [2] 17 3c [2] 15 3d [2] 0e 3b [2] 12 3c [2] 0e 13 }

  condition:
    any of them
}