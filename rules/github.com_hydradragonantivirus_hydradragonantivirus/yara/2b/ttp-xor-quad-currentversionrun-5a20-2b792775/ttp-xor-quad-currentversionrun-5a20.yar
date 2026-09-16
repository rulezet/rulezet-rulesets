rule TTP_XOR_QUAD_CurrentVersionRun_5a20 {
  strings:
    $key_5a20 = { 09 4f [2] 2d 41 [2] 06 6d [2] 28 4f [2] 3c 54 [2] 33 4e [2] 2d 53 [2] 2f 52 [2] 34 54 [2] 28 53 [2] 34 7c }

  condition:
    any of them
}