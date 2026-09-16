rule TTP_XOR_QUAD_CurrentVersionRun_7171 {
  strings:
    $key_7171 = { 22 1e [2] 06 10 [2] 2d 3c [2] 03 1e [2] 17 05 [2] 18 1f [2] 06 02 [2] 04 03 [2] 1f 05 [2] 03 02 [2] 1f 2d }

  condition:
    any of them
}