rule TTP_XOR_QUAD_CurrentVersionRun_3e00 {
  strings:
    $key_3e00 = { 6d 6f [2] 49 61 [2] 62 4d [2] 4c 6f [2] 58 74 [2] 57 6e [2] 49 73 [2] 4b 72 [2] 50 74 [2] 4c 73 [2] 50 5c }

  condition:
    any of them
}