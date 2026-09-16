rule TTP_XOR_QUAD_CurrentVersionRun_716a {
  strings:
    $key_716a = { 22 05 [2] 06 0b [2] 2d 27 [2] 03 05 [2] 17 1e [2] 18 04 [2] 06 19 [2] 04 18 [2] 1f 1e [2] 03 19 [2] 1f 36 }

  condition:
    any of them
}