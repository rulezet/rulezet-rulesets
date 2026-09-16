rule TTP_XOR_QUAD_CurrentVersionRun_0b20 {
  strings:
    $key_0b20 = { 58 4f [2] 7c 41 [2] 57 6d [2] 79 4f [2] 6d 54 [2] 62 4e [2] 7c 53 [2] 7e 52 [2] 65 54 [2] 79 53 [2] 65 7c }

  condition:
    any of them
}