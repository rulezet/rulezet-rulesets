rule TTP_XOR_QUAD_CurrentVersionRun_7b02 {
  strings:
    $key_7b02 = { 28 6d [2] 0c 63 [2] 27 4f [2] 09 6d [2] 1d 76 [2] 12 6c [2] 0c 71 [2] 0e 70 [2] 15 76 [2] 09 71 [2] 15 5e }

  condition:
    any of them
}