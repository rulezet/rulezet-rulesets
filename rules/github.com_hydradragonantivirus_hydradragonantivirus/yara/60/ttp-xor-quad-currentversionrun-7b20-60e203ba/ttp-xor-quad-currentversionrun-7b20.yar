rule TTP_XOR_QUAD_CurrentVersionRun_7b20 {
  strings:
    $key_7b20 = { 28 4f [2] 0c 41 [2] 27 6d [2] 09 4f [2] 1d 54 [2] 12 4e [2] 0c 53 [2] 0e 52 [2] 15 54 [2] 09 53 [2] 15 7c }

  condition:
    any of them
}