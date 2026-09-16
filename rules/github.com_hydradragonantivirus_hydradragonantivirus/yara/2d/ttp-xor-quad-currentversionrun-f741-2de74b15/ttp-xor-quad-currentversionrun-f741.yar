rule TTP_XOR_QUAD_CurrentVersionRun_f741 {
  strings:
    $key_f741 = { a4 2e [2] 80 20 [2] ab 0c [2] 85 2e [2] 91 35 [2] 9e 2f [2] 80 32 [2] 82 33 [2] 99 35 [2] 85 32 [2] 99 1d }

  condition:
    any of them
}