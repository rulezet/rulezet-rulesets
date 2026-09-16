rule TTP_XOR_QUAD_CurrentVersionRun_4112 {
  strings:
    $key_4112 = { 12 7d [2] 36 73 [2] 1d 5f [2] 33 7d [2] 27 66 [2] 28 7c [2] 36 61 [2] 34 60 [2] 2f 66 [2] 33 61 [2] 2f 4e }

  condition:
    any of them
}