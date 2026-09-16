rule TTP_XOR_QUAD_CurrentVersionRun_361c {
  strings:
    $key_361c = { 65 73 [2] 41 7d [2] 6a 51 [2] 44 73 [2] 50 68 [2] 5f 72 [2] 41 6f [2] 43 6e [2] 58 68 [2] 44 6f [2] 58 40 }

  condition:
    any of them
}