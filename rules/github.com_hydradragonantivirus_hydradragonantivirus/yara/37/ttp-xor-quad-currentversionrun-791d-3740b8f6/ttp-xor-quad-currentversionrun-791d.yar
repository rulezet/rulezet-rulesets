rule TTP_XOR_QUAD_CurrentVersionRun_791d {
  strings:
    $key_791d = { 2a 72 [2] 0e 7c [2] 25 50 [2] 0b 72 [2] 1f 69 [2] 10 73 [2] 0e 6e [2] 0c 6f [2] 17 69 [2] 0b 6e [2] 17 41 }

  condition:
    any of them
}