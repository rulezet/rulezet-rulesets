rule TTP_XOR_QUAD_CurrentVersionRun_0100 {
  strings:
    $key_0100 = { 52 6f [2] 76 61 [2] 5d 4d [2] 73 6f [2] 67 74 [2] 68 6e [2] 76 73 [2] 74 72 [2] 6f 74 [2] 73 73 [2] 6f 5c }

  condition:
    any of them
}