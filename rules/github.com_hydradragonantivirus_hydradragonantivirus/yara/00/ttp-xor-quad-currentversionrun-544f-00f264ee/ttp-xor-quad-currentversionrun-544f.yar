rule TTP_XOR_QUAD_CurrentVersionRun_544f {
  strings:
    $key_544f = { 07 20 [2] 23 2e [2] 08 02 [2] 26 20 [2] 32 3b [2] 3d 21 [2] 23 3c [2] 21 3d [2] 3a 3b [2] 26 3c [2] 3a 13 }

  condition:
    any of them
}