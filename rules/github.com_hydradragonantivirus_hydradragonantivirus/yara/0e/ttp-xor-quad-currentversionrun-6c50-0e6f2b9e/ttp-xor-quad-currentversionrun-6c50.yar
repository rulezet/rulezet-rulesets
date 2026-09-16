rule TTP_XOR_QUAD_CurrentVersionRun_6c50 {
  strings:
    $key_6c50 = { 3f 3f [2] 1b 31 [2] 30 1d [2] 1e 3f [2] 0a 24 [2] 05 3e [2] 1b 23 [2] 19 22 [2] 02 24 [2] 1e 23 [2] 02 0c }

  condition:
    any of them
}