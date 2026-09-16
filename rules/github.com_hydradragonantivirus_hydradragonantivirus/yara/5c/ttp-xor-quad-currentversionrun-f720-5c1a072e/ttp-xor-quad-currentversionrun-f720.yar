rule TTP_XOR_QUAD_CurrentVersionRun_f720 {
  strings:
    $key_f720 = { a4 4f [2] 80 41 [2] ab 6d [2] 85 4f [2] 91 54 [2] 9e 4e [2] 80 53 [2] 82 52 [2] 99 54 [2] 85 53 [2] 99 7c }

  condition:
    any of them
}