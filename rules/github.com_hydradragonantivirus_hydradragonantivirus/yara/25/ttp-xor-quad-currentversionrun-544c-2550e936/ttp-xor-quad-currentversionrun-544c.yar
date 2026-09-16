rule TTP_XOR_QUAD_CurrentVersionRun_544c {
  strings:
    $key_544c = { 07 23 [2] 23 2d [2] 08 01 [2] 26 23 [2] 32 38 [2] 3d 22 [2] 23 3f [2] 21 3e [2] 3a 38 [2] 26 3f [2] 3a 10 }

  condition:
    any of them
}