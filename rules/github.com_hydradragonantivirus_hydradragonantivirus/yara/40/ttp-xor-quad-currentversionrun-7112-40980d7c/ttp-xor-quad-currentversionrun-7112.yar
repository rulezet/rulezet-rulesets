rule TTP_XOR_QUAD_CurrentVersionRun_7112 {
  strings:
    $key_7112 = { 22 7d [2] 06 73 [2] 2d 5f [2] 03 7d [2] 17 66 [2] 18 7c [2] 06 61 [2] 04 60 [2] 1f 66 [2] 03 61 [2] 1f 4e }

  condition:
    any of them
}