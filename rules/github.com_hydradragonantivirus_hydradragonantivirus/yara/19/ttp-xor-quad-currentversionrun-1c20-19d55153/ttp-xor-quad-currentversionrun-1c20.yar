rule TTP_XOR_QUAD_CurrentVersionRun_1c20 {
  strings:
    $key_1c20 = { 4f 4f [2] 6b 41 [2] 40 6d [2] 6e 4f [2] 7a 54 [2] 75 4e [2] 6b 53 [2] 69 52 [2] 72 54 [2] 6e 53 [2] 72 7c }

  condition:
    any of them
}