rule TTP_XOR_QUAD_CurrentVersionRun_536c {
  strings:
    $key_536c = { 00 03 [2] 24 0d [2] 0f 21 [2] 21 03 [2] 35 18 [2] 3a 02 [2] 24 1f [2] 26 1e [2] 3d 18 [2] 21 1f [2] 3d 30 }

  condition:
    any of them
}