rule TTP_XOR_QUAD_CurrentVersionRun_201c {
  strings:
    $key_201c = { 73 73 [2] 57 7d [2] 7c 51 [2] 52 73 [2] 46 68 [2] 49 72 [2] 57 6f [2] 55 6e [2] 4e 68 [2] 52 6f [2] 4e 40 }

  condition:
    any of them
}