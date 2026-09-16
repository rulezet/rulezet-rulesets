rule TTP_XOR_QUAD_CurrentVersionRun_0950 {
  strings:
    $key_0950 = { 5a 3f [2] 7e 31 [2] 55 1d [2] 7b 3f [2] 6f 24 [2] 60 3e [2] 7e 23 [2] 7c 22 [2] 67 24 [2] 7b 23 [2] 67 0c }

  condition:
    any of them
}