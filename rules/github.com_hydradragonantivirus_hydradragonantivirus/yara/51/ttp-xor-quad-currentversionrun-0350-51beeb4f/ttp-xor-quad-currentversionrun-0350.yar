rule TTP_XOR_QUAD_CurrentVersionRun_0350 {
  strings:
    $key_0350 = { 50 3f [2] 74 31 [2] 5f 1d [2] 71 3f [2] 65 24 [2] 6a 3e [2] 74 23 [2] 76 22 [2] 6d 24 [2] 71 23 [2] 6d 0c }

  condition:
    any of them
}