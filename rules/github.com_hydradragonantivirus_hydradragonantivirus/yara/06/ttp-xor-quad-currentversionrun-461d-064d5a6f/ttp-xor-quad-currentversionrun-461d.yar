rule TTP_XOR_QUAD_CurrentVersionRun_461d {
  strings:
    $key_461d = { 15 72 [2] 31 7c [2] 1a 50 [2] 34 72 [2] 20 69 [2] 2f 73 [2] 31 6e [2] 33 6f [2] 28 69 [2] 34 6e [2] 28 41 }

  condition:
    any of them
}