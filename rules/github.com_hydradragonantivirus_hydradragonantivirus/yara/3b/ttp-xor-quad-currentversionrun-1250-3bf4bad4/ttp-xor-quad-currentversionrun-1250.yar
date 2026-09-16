rule TTP_XOR_QUAD_CurrentVersionRun_1250 {
  strings:
    $key_1250 = { 41 3f [2] 65 31 [2] 4e 1d [2] 60 3f [2] 74 24 [2] 7b 3e [2] 65 23 [2] 67 22 [2] 7c 24 [2] 60 23 [2] 7c 0c }

  condition:
    any of them
}