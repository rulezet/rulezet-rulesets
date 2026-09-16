rule TTP_XOR_QUAD_CurrentVersionRun_614c {
  strings:
    $key_614c = { 32 23 [2] 16 2d [2] 3d 01 [2] 13 23 [2] 07 38 [2] 08 22 [2] 16 3f [2] 14 3e [2] 0f 38 [2] 13 3f [2] 0f 10 }

  condition:
    any of them
}