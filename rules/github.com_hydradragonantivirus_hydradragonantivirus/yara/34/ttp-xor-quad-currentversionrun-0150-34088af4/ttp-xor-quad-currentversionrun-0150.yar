rule TTP_XOR_QUAD_CurrentVersionRun_0150 {
  strings:
    $key_0150 = { 52 3f [2] 76 31 [2] 5d 1d [2] 73 3f [2] 67 24 [2] 68 3e [2] 76 23 [2] 74 22 [2] 6f 24 [2] 73 23 [2] 6f 0c }

  condition:
    any of them
}