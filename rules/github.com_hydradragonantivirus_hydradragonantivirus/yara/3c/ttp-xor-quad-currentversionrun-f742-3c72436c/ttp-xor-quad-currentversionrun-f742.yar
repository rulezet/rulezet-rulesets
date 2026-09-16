rule TTP_XOR_QUAD_CurrentVersionRun_f742 {
  strings:
    $key_f742 = { a4 2d [2] 80 23 [2] ab 0f [2] 85 2d [2] 91 36 [2] 9e 2c [2] 80 31 [2] 82 30 [2] 99 36 [2] 85 31 [2] 99 1e }

  condition:
    any of them
}