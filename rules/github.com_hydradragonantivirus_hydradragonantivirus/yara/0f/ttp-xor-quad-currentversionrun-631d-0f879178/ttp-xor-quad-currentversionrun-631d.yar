rule TTP_XOR_QUAD_CurrentVersionRun_631d {
  strings:
    $key_631d = { 30 72 [2] 14 7c [2] 3f 50 [2] 11 72 [2] 05 69 [2] 0a 73 [2] 14 6e [2] 16 6f [2] 0d 69 [2] 11 6e [2] 0d 41 }

  condition:
    any of them
}