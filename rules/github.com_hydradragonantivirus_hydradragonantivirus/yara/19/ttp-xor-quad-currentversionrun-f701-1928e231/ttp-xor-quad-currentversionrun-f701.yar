rule TTP_XOR_QUAD_CurrentVersionRun_f701 {
  strings:
    $key_f701 = { a4 6e [2] 80 60 [2] ab 4c [2] 85 6e [2] 91 75 [2] 9e 6f [2] 80 72 [2] 82 73 [2] 99 75 [2] 85 72 [2] 99 5d }

  condition:
    any of them
}