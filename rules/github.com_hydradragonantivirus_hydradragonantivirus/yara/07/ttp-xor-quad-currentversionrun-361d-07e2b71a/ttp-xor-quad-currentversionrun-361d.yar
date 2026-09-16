rule TTP_XOR_QUAD_CurrentVersionRun_361d {
  strings:
    $key_361d = { 65 72 [2] 41 7c [2] 6a 50 [2] 44 72 [2] 50 69 [2] 5f 73 [2] 41 6e [2] 43 6f [2] 58 69 [2] 44 6e [2] 58 41 }

  condition:
    any of them
}