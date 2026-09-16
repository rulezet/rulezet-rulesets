rule TTP_XOR_QUAD_CurrentVersionRun_1300 {
  strings:
    $key_1300 = { 40 6f [2] 64 61 [2] 4f 4d [2] 61 6f [2] 75 74 [2] 7a 6e [2] 64 73 [2] 66 72 [2] 7d 74 [2] 61 73 [2] 7d 5c }

  condition:
    any of them
}