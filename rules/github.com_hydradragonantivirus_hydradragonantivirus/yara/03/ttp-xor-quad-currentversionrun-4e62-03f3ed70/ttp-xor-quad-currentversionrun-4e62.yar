rule TTP_XOR_QUAD_CurrentVersionRun_4e62 {
  strings:
    $key_4e62 = { 1d 0d [2] 39 03 [2] 12 2f [2] 3c 0d [2] 28 16 [2] 27 0c [2] 39 11 [2] 3b 10 [2] 20 16 [2] 3c 11 [2] 20 3e }

  condition:
    any of them
}