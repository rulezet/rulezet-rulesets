rule TTP_XOR_QUAD_CurrentVersionRun_011d {
  strings:
    $key_011d = { 52 72 [2] 76 7c [2] 5d 50 [2] 73 72 [2] 67 69 [2] 68 73 [2] 76 6e [2] 74 6f [2] 6f 69 [2] 73 6e [2] 6f 41 }

  condition:
    any of them
}