rule TTP_XOR_QUAD_CurrentVersionRun_1a00 {
  strings:
    $key_1a00 = { 49 6f [2] 6d 61 [2] 46 4d [2] 68 6f [2] 7c 74 [2] 73 6e [2] 6d 73 [2] 6f 72 [2] 74 74 [2] 68 73 [2] 74 5c }

  condition:
    any of them
}