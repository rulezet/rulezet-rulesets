rule TTP_XOR_QUAD_CurrentVersionRun_0650 {
  strings:
    $key_0650 = { 55 3f [2] 71 31 [2] 5a 1d [2] 74 3f [2] 60 24 [2] 6f 3e [2] 71 23 [2] 73 22 [2] 68 24 [2] 74 23 [2] 68 0c }

  condition:
    any of them
}