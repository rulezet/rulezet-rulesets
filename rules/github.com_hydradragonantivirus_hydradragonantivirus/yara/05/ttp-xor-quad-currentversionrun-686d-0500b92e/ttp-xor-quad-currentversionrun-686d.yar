rule TTP_XOR_QUAD_CurrentVersionRun_686d {
  strings:
    $key_686d = { 3b 02 [2] 1f 0c [2] 34 20 [2] 1a 02 [2] 0e 19 [2] 01 03 [2] 1f 1e [2] 1d 1f [2] 06 19 [2] 1a 1e [2] 06 31 }

  condition:
    any of them
}