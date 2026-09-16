rule TTP_XOR_QUAD_CurrentVersionRun_0c20 {
  strings:
    $key_0c20 = { 5f 4f [2] 7b 41 [2] 50 6d [2] 7e 4f [2] 6a 54 [2] 65 4e [2] 7b 53 [2] 79 52 [2] 62 54 [2] 7e 53 [2] 62 7c }

  condition:
    any of them
}