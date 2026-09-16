rule TTP_XOR_QUAD_CurrentVersionRun_f71d {
  strings:
    $key_f71d = { a4 72 [2] 80 7c [2] ab 50 [2] 85 72 [2] 91 69 [2] 9e 73 [2] 80 6e [2] 82 6f [2] 99 69 [2] 85 6e [2] 99 41 }

  condition:
    any of them
}