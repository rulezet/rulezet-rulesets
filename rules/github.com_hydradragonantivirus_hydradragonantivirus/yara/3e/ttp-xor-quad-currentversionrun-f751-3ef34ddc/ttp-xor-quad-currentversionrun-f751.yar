rule TTP_XOR_QUAD_CurrentVersionRun_f751 {
  strings:
    $key_f751 = { a4 3e [2] 80 30 [2] ab 1c [2] 85 3e [2] 91 25 [2] 9e 3f [2] 80 22 [2] 82 23 [2] 99 25 [2] 85 22 [2] 99 0d }

  condition:
    any of them
}