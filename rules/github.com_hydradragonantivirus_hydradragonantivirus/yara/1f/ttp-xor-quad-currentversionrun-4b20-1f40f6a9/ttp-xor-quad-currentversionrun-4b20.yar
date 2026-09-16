rule TTP_XOR_QUAD_CurrentVersionRun_4b20 {
  strings:
    $key_4b20 = { 18 4f [2] 3c 41 [2] 17 6d [2] 39 4f [2] 2d 54 [2] 22 4e [2] 3c 53 [2] 3e 52 [2] 25 54 [2] 39 53 [2] 25 7c }

  condition:
    any of them
}