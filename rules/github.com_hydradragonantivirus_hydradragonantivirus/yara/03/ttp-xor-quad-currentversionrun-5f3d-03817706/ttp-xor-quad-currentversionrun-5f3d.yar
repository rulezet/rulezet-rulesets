rule TTP_XOR_QUAD_CurrentVersionRun_5f3d {
  strings:
    $key_5f3d = { 0c 52 [2] 28 5c [2] 03 70 [2] 2d 52 [2] 39 49 [2] 36 53 [2] 28 4e [2] 2a 4f [2] 31 49 [2] 2d 4e [2] 31 61 }

  condition:
    any of them
}