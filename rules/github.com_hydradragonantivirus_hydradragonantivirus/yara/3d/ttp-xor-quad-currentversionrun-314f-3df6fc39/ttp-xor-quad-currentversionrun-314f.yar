rule TTP_XOR_QUAD_CurrentVersionRun_314f {
  strings:
    $key_314f = { 62 20 [2] 46 2e [2] 6d 02 [2] 43 20 [2] 57 3b [2] 58 21 [2] 46 3c [2] 44 3d [2] 5f 3b [2] 43 3c [2] 5f 13 }

  condition:
    any of them
}