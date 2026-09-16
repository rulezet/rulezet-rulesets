rule TTP_XOR_QUAD_CurrentVersionRun_5772 {
  strings:
    $key_5772 = { 04 1d [2] 20 13 [2] 0b 3f [2] 25 1d [2] 31 06 [2] 3e 1c [2] 20 01 [2] 22 00 [2] 39 06 [2] 25 01 [2] 39 2e }

  condition:
    any of them
}