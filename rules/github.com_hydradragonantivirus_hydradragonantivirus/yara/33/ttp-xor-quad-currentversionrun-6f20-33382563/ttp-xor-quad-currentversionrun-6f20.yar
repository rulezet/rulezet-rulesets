rule TTP_XOR_QUAD_CurrentVersionRun_6f20 {
  strings:
    $key_6f20 = { 3c 4f [2] 18 41 [2] 33 6d [2] 1d 4f [2] 09 54 [2] 06 4e [2] 18 53 [2] 1a 52 [2] 01 54 [2] 1d 53 [2] 01 7c }

  condition:
    any of them
}