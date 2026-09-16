rule TTP_XOR_QUAD_CurrentVersionRun_6320 {
  strings:
    $key_6320 = { 30 4f [2] 14 41 [2] 3f 6d [2] 11 4f [2] 05 54 [2] 0a 4e [2] 14 53 [2] 16 52 [2] 0d 54 [2] 11 53 [2] 0d 7c }

  condition:
    any of them
}