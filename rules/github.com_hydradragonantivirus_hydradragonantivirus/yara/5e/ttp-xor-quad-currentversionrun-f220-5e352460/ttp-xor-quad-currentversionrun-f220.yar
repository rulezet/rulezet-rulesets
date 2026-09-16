rule TTP_XOR_QUAD_CurrentVersionRun_f220 {
  strings:
    $key_f220 = { a1 4f [2] 85 41 [2] ae 6d [2] 80 4f [2] 94 54 [2] 9b 4e [2] 85 53 [2] 87 52 [2] 9c 54 [2] 80 53 [2] 9c 7c }

  condition:
    any of them
}