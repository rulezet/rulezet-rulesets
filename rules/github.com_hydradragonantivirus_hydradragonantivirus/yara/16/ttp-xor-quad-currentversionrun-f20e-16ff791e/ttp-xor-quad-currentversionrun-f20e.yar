rule TTP_XOR_QUAD_CurrentVersionRun_f20e {
  strings:
    $key_f20e = { a1 61 [2] 85 6f [2] ae 43 [2] 80 61 [2] 94 7a [2] 9b 60 [2] 85 7d [2] 87 7c [2] 9c 7a [2] 80 7d [2] 9c 52 }

  condition:
    any of them
}