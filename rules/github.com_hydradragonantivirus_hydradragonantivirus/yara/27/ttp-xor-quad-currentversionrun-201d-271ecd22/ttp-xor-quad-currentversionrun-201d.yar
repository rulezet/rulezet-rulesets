rule TTP_XOR_QUAD_CurrentVersionRun_201d {
  strings:
    $key_201d = { 73 72 [2] 57 7c [2] 7c 50 [2] 52 72 [2] 46 69 [2] 49 73 [2] 57 6e [2] 55 6f [2] 4e 69 [2] 52 6e [2] 4e 41 }

  condition:
    any of them
}