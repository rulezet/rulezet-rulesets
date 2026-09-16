rule TTP_XOR_QUAD_CurrentVersionRun_e000 {
  strings:
    $key_e000 = { b3 6f [2] 97 61 [2] bc 4d [2] 92 6f [2] 86 74 [2] 89 6e [2] 97 73 [2] 95 72 [2] 8e 74 [2] 92 73 [2] 8e 5c }

  condition:
    any of them
}