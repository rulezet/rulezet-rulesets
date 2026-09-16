rule TTP_XOR_QUAD_CurrentVersionRun_6c20 {
  strings:
    $key_6c20 = { 3f 4f [2] 1b 41 [2] 30 6d [2] 1e 4f [2] 0a 54 [2] 05 4e [2] 1b 53 [2] 19 52 [2] 02 54 [2] 1e 53 [2] 02 7c }

  condition:
    any of them
}