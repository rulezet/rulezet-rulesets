rule TTP_XOR_QUAD_CurrentVersionRun_533c {
  strings:
    $key_533c = { 00 53 [2] 24 5d [2] 0f 71 [2] 21 53 [2] 35 48 [2] 3a 52 [2] 24 4f [2] 26 4e [2] 3d 48 [2] 21 4f [2] 3d 60 }

  condition:
    any of them
}