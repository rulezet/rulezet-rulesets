rule TTP_XOR_QUAD_CurrentVersionRun_f00e {
  strings:
    $key_f00e = { a3 61 [2] 87 6f [2] ac 43 [2] 82 61 [2] 96 7a [2] 99 60 [2] 87 7d [2] 85 7c [2] 9e 7a [2] 82 7d [2] 9e 52 }

  condition:
    any of them
}