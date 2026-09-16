rule TTP_XOR_QUAD_CurrentVersionRun_4e20 {
  strings:
    $key_4e20 = { 1d 4f [2] 39 41 [2] 12 6d [2] 3c 4f [2] 28 54 [2] 27 4e [2] 39 53 [2] 3b 52 [2] 20 54 [2] 3c 53 [2] 20 7c }

  condition:
    any of them
}