rule TTP_XOR_QUAD_CurrentVersionRun_3400 {
  strings:
    $key_3400 = { 67 6f [2] 43 61 [2] 68 4d [2] 46 6f [2] 52 74 [2] 5d 6e [2] 43 73 [2] 41 72 [2] 5a 74 [2] 46 73 [2] 5a 5c }

  condition:
    any of them
}