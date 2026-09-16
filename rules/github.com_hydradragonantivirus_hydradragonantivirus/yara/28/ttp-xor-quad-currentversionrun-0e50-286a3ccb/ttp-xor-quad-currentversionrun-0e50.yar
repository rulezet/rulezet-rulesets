rule TTP_XOR_QUAD_CurrentVersionRun_0e50 {
  strings:
    $key_0e50 = { 5d 3f [2] 79 31 [2] 52 1d [2] 7c 3f [2] 68 24 [2] 67 3e [2] 79 23 [2] 7b 22 [2] 60 24 [2] 7c 23 [2] 60 0c }

  condition:
    any of them
}