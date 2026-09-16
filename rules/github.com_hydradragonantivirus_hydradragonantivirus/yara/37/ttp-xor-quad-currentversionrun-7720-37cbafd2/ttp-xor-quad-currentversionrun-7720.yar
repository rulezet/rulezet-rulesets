rule TTP_XOR_QUAD_CurrentVersionRun_7720 {
  strings:
    $key_7720 = { 24 4f [2] 00 41 [2] 2b 6d [2] 05 4f [2] 11 54 [2] 1e 4e [2] 00 53 [2] 02 52 [2] 19 54 [2] 05 53 [2] 19 7c }

  condition:
    any of them
}