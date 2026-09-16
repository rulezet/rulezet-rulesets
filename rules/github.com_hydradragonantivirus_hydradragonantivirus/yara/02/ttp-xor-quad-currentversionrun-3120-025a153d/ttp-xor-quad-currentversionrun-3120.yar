rule TTP_XOR_QUAD_CurrentVersionRun_3120 {
  strings:
    $key_3120 = { 62 4f [2] 46 41 [2] 6d 6d [2] 43 4f [2] 57 54 [2] 58 4e [2] 46 53 [2] 44 52 [2] 5f 54 [2] 43 53 [2] 5f 7c }

  condition:
    any of them
}