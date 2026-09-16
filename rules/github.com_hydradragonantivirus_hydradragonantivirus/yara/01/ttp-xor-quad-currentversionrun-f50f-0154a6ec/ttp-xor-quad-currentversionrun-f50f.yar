rule TTP_XOR_QUAD_CurrentVersionRun_f50f {
  strings:
    $key_f50f = { a6 60 [2] 82 6e [2] a9 42 [2] 87 60 [2] 93 7b [2] 9c 61 [2] 82 7c [2] 80 7d [2] 9b 7b [2] 87 7c [2] 9b 53 }

  condition:
    any of them
}