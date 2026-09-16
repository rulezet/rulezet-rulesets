rule TTP_XOR_QUAD_CurrentVersionRun_514f {
  strings:
    $key_514f = { 02 20 [2] 26 2e [2] 0d 02 [2] 23 20 [2] 37 3b [2] 38 21 [2] 26 3c [2] 24 3d [2] 3f 3b [2] 23 3c [2] 3f 13 }

  condition:
    any of them
}