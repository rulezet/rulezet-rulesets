rule TTP_XOR_QUAD_CurrentVersionRun_f70a {
  strings:
    $key_f70a = { a4 65 [2] 80 6b [2] ab 47 [2] 85 65 [2] 91 7e [2] 9e 64 [2] 80 79 [2] 82 78 [2] 99 7e [2] 85 79 [2] 99 56 }

  condition:
    any of them
}