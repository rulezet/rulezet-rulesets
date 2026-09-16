rule TTP_XOR_QUAD_CurrentVersionRun_4c20 {
  strings:
    $key_4c20 = { 1f 4f [2] 3b 41 [2] 10 6d [2] 3e 4f [2] 2a 54 [2] 25 4e [2] 3b 53 [2] 39 52 [2] 22 54 [2] 3e 53 [2] 22 7c }

  condition:
    any of them
}