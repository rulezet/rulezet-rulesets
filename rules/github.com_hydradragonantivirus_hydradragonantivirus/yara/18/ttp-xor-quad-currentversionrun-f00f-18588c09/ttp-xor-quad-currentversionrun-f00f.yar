rule TTP_XOR_QUAD_CurrentVersionRun_f00f {
  strings:
    $key_f00f = { a3 60 [2] 87 6e [2] ac 42 [2] 82 60 [2] 96 7b [2] 99 61 [2] 87 7c [2] 85 7d [2] 9e 7b [2] 82 7c [2] 9e 53 }

  condition:
    any of them
}