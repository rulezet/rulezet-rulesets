rule TTP_XOR_QUAD_CurrentVersionRun_716d {
  strings:
    $key_716d = { 22 02 [2] 06 0c [2] 2d 20 [2] 03 02 [2] 17 19 [2] 18 03 [2] 06 1e [2] 04 1f [2] 1f 19 [2] 03 1e [2] 1f 31 }

  condition:
    any of them
}