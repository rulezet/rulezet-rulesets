rule TTP_XOR_QUAD_CurrentVersionRun_3320 {
  strings:
    $key_3320 = { 60 4f [2] 44 41 [2] 6f 6d [2] 41 4f [2] 55 54 [2] 5a 4e [2] 44 53 [2] 46 52 [2] 5d 54 [2] 41 53 [2] 5d 7c }

  condition:
    any of them
}