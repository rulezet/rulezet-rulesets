rule TTP_XOR_QUAD_CurrentVersionRun_7e20 {
  strings:
    $key_7e20 = { 2d 4f [2] 09 41 [2] 22 6d [2] 0c 4f [2] 18 54 [2] 17 4e [2] 09 53 [2] 0b 52 [2] 10 54 [2] 0c 53 [2] 10 7c }

  condition:
    any of them
}