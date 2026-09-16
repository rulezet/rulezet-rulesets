rule TTP_XOR_QUAD_CurrentVersionRun_f7f0 {
  strings:
    $key_f7f0 = { a4 9f [2] 80 91 [2] ab bd [2] 85 9f [2] 91 84 [2] 9e 9e [2] 80 83 [2] 82 82 [2] 99 84 [2] 85 83 [2] 99 ac }

  condition:
    any of them
}