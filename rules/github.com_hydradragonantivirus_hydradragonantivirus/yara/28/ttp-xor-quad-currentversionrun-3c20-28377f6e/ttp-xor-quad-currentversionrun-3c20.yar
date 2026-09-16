rule TTP_XOR_QUAD_CurrentVersionRun_3c20 {
  strings:
    $key_3c20 = { 6f 4f [2] 4b 41 [2] 60 6d [2] 4e 4f [2] 5a 54 [2] 55 4e [2] 4b 53 [2] 49 52 [2] 52 54 [2] 4e 53 [2] 52 7c }

  condition:
    any of them
}