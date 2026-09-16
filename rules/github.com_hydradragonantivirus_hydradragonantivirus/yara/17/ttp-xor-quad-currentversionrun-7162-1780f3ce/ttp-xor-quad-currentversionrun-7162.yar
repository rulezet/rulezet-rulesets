rule TTP_XOR_QUAD_CurrentVersionRun_7162 {
  strings:
    $key_7162 = { 22 0d [2] 06 03 [2] 2d 2f [2] 03 0d [2] 17 16 [2] 18 0c [2] 06 11 [2] 04 10 [2] 1f 16 [2] 03 11 [2] 1f 3e }

  condition:
    any of them
}