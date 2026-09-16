rule TTP_XOR_QUAD_CurrentVersionRun_7312 {
  strings:
    $key_7312 = { 20 7d [2] 04 73 [2] 2f 5f [2] 01 7d [2] 15 66 [2] 1a 7c [2] 04 61 [2] 06 60 [2] 1d 66 [2] 01 61 [2] 1d 4e }

  condition:
    any of them
}