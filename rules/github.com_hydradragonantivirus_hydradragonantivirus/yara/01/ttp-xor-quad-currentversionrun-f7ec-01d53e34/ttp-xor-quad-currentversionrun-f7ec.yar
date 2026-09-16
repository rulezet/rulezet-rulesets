rule TTP_XOR_QUAD_CurrentVersionRun_f7ec {
  strings:
    $key_f7ec = { a4 83 [2] 80 8d [2] ab a1 [2] 85 83 [2] 91 98 [2] 9e 82 [2] 80 9f [2] 82 9e [2] 99 98 [2] 85 9f [2] 99 b0 }

  condition:
    any of them
}