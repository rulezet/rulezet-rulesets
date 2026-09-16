rule TTP_XOR_QUAD_CurrentVersionRun_7121 {
  strings:
    $key_7121 = { 22 4e [2] 06 40 [2] 2d 6c [2] 03 4e [2] 17 55 [2] 18 4f [2] 06 52 [2] 04 53 [2] 1f 55 [2] 03 52 [2] 1f 7d }

  condition:
    any of them
}