rule TTP_XOR_QUAD_CurrentVersionRun_7350 {
  strings:
    $key_7350 = { 20 3f [2] 04 31 [2] 2f 1d [2] 01 3f [2] 15 24 [2] 1a 3e [2] 04 23 [2] 06 22 [2] 1d 24 [2] 01 23 [2] 1d 0c }

  condition:
    any of them
}