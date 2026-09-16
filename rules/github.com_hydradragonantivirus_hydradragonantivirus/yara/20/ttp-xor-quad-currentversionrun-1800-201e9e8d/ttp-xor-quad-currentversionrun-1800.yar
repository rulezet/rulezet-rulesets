rule TTP_XOR_QUAD_CurrentVersionRun_1800 {
  strings:
    $key_1800 = { 4b 6f [2] 6f 61 [2] 44 4d [2] 6a 6f [2] 7e 74 [2] 71 6e [2] 6f 73 [2] 6d 72 [2] 76 74 [2] 6a 73 [2] 76 5c }

  condition:
    any of them
}