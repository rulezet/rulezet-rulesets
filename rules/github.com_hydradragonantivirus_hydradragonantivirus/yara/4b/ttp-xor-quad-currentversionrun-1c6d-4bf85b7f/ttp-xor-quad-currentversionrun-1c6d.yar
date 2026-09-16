rule TTP_XOR_QUAD_CurrentVersionRun_1c6d {
  strings:
    $key_1c6d = { 4f 02 [2] 6b 0c [2] 40 20 [2] 6e 02 [2] 7a 19 [2] 75 03 [2] 6b 1e [2] 69 1f [2] 72 19 [2] 6e 1e [2] 72 31 }

  condition:
    any of them
}