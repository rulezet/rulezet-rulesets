rule TTP_XOR_QUAD_CurrentVersionRun_6c00 {
  strings:
    $key_6c00 = { 3f 6f [2] 1b 61 [2] 30 4d [2] 1e 6f [2] 0a 74 [2] 05 6e [2] 1b 73 [2] 19 72 [2] 02 74 [2] 1e 73 [2] 02 5c }

  condition:
    any of them
}