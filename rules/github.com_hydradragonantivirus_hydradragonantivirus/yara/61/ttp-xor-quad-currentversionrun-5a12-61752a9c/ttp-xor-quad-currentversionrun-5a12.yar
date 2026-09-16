rule TTP_XOR_QUAD_CurrentVersionRun_5a12 {
  strings:
    $key_5a12 = { 09 7d [2] 2d 73 [2] 06 5f [2] 28 7d [2] 3c 66 [2] 33 7c [2] 2d 61 [2] 2f 60 [2] 34 66 [2] 28 61 [2] 34 4e }

  condition:
    any of them
}