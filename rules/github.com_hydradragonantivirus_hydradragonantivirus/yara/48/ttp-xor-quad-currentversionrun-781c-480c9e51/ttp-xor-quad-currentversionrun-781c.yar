rule TTP_XOR_QUAD_CurrentVersionRun_781c {
  strings:
    $key_781c = { 2b 73 [2] 0f 7d [2] 24 51 [2] 0a 73 [2] 1e 68 [2] 11 72 [2] 0f 6f [2] 0d 6e [2] 16 68 [2] 0a 6f [2] 16 40 }

  condition:
    any of them
}