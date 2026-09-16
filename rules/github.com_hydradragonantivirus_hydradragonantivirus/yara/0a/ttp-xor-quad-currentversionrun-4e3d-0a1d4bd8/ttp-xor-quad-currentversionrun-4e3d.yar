rule TTP_XOR_QUAD_CurrentVersionRun_4e3d {
  strings:
    $key_4e3d = { 1d 52 [2] 39 5c [2] 12 70 [2] 3c 52 [2] 28 49 [2] 27 53 [2] 39 4e [2] 3b 4f [2] 20 49 [2] 3c 4e [2] 20 61 }

  condition:
    any of them
}