rule TTP_XOR_QUAD_CurrentVersionRun_0e00 {
  strings:
    $key_0e00 = { 5d 6f [2] 79 61 [2] 52 4d [2] 7c 6f [2] 68 74 [2] 67 6e [2] 79 73 [2] 7b 72 [2] 60 74 [2] 7c 73 [2] 60 5c }

  condition:
    any of them
}