rule TTP_XOR_QUAD_CurrentVersionRun_1100 {
  strings:
    $key_1100 = { 42 6f [2] 66 61 [2] 4d 4d [2] 63 6f [2] 77 74 [2] 78 6e [2] 66 73 [2] 64 72 [2] 7f 74 [2] 63 73 [2] 7f 5c }

  condition:
    any of them
}