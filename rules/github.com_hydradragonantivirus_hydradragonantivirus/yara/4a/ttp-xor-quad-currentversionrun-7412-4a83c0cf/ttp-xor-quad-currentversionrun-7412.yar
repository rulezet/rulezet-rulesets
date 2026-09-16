rule TTP_XOR_QUAD_CurrentVersionRun_7412 {
  strings:
    $key_7412 = { 27 7d [2] 03 73 [2] 28 5f [2] 06 7d [2] 12 66 [2] 1d 7c [2] 03 61 [2] 01 60 [2] 1a 66 [2] 06 61 [2] 1a 4e }

  condition:
    any of them
}