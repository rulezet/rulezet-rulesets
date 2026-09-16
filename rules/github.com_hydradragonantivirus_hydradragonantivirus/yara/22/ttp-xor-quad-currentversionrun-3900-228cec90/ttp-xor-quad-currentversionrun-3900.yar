rule TTP_XOR_QUAD_CurrentVersionRun_3900 {
  strings:
    $key_3900 = { 6a 6f [2] 4e 61 [2] 65 4d [2] 4b 6f [2] 5f 74 [2] 50 6e [2] 4e 73 [2] 4c 72 [2] 57 74 [2] 4b 73 [2] 57 5c }

  condition:
    any of them
}