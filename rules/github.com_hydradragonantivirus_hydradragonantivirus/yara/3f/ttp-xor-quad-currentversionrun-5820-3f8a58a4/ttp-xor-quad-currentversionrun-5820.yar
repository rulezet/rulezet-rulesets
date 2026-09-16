rule TTP_XOR_QUAD_CurrentVersionRun_5820 {
  strings:
    $key_5820 = { 0b 4f [2] 2f 41 [2] 04 6d [2] 2a 4f [2] 3e 54 [2] 31 4e [2] 2f 53 [2] 2d 52 [2] 36 54 [2] 2a 53 [2] 36 7c }

  condition:
    any of them
}