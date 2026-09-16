rule TTP_XOR_QUAD_CurrentVersionRun_1c6c {
  strings:
    $key_1c6c = { 4f 03 [2] 6b 0d [2] 40 21 [2] 6e 03 [2] 7a 18 [2] 75 02 [2] 6b 1f [2] 69 1e [2] 72 18 [2] 6e 1f [2] 72 30 }

  condition:
    any of them
}