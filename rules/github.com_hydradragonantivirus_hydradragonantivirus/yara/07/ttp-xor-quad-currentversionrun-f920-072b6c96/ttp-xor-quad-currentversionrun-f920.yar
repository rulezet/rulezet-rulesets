rule TTP_XOR_QUAD_CurrentVersionRun_f920 {
  strings:
    $key_f920 = { aa 4f [2] 8e 41 [2] a5 6d [2] 8b 4f [2] 9f 54 [2] 90 4e [2] 8e 53 [2] 8c 52 [2] 97 54 [2] 8b 53 [2] 97 7c }

  condition:
    any of them
}