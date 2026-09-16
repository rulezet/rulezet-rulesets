rule TTP_XOR_QUAD_CurrentVersionRun_6a62 {
  strings:
    $key_6a62 = { 39 0d [2] 1d 03 [2] 36 2f [2] 18 0d [2] 0c 16 [2] 03 0c [2] 1d 11 [2] 1f 10 [2] 04 16 [2] 18 11 [2] 04 3e }

  condition:
    any of them
}