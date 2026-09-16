rule TTP_XOR_QUAD_CurrentVersionRun_2163 {
  strings:
    $key_2163 = { 72 0c [2] 56 02 [2] 7d 2e [2] 53 0c [2] 47 17 [2] 48 0d [2] 56 10 [2] 54 11 [2] 4f 17 [2] 53 10 [2] 4f 3f }

  condition:
    any of them
}