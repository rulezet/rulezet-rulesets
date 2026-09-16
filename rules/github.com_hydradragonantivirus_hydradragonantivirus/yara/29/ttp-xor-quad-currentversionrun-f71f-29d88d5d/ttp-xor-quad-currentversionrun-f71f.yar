rule TTP_XOR_QUAD_CurrentVersionRun_f71f {
  strings:
    $key_f71f = { a4 70 [2] 80 7e [2] ab 52 [2] 85 70 [2] 91 6b [2] 9e 71 [2] 80 6c [2] 82 6d [2] 99 6b [2] 85 6c [2] 99 43 }

  condition:
    any of them
}