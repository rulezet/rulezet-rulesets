rule TTP_XOR_QUAD_CurrentVersionRun_404f {
  strings:
    $key_404f = { 13 20 [2] 37 2e [2] 1c 02 [2] 32 20 [2] 26 3b [2] 29 21 [2] 37 3c [2] 35 3d [2] 2e 3b [2] 32 3c [2] 2e 13 }

  condition:
    any of them
}