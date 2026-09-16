rule TTP_XOR_QUAD_CurrentVersionRun_0156 {
  strings:
    $key_0156 = { 52 39 [2] 76 37 [2] 5d 1b [2] 73 39 [2] 67 22 [2] 68 38 [2] 76 25 [2] 74 24 [2] 6f 22 [2] 73 25 [2] 6f 0a }

  condition:
    any of them
}