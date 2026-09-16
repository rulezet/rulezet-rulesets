rule TTP_XOR_QUAD_CurrentVersionRun_1820 {
  strings:
    $key_1820 = { 4b 4f [2] 6f 41 [2] 44 6d [2] 6a 4f [2] 7e 54 [2] 71 4e [2] 6f 53 [2] 6d 52 [2] 76 54 [2] 6a 53 [2] 76 7c }

  condition:
    any of them
}