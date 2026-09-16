rule TTP_XOR_QUAD_CurrentVersionRun_1720 {
  strings:
    $key_1720 = { 44 4f [2] 60 41 [2] 4b 6d [2] 65 4f [2] 71 54 [2] 7e 4e [2] 60 53 [2] 62 52 [2] 79 54 [2] 65 53 [2] 79 7c }

  condition:
    any of them
}