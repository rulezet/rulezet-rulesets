rule TTP_XOR_QUAD_CurrentVersionRun_716c {
  strings:
    $key_716c = { 22 03 [2] 06 0d [2] 2d 21 [2] 03 03 [2] 17 18 [2] 18 02 [2] 06 1f [2] 04 1e [2] 1f 18 [2] 03 1f [2] 1f 30 }

  condition:
    any of them
}