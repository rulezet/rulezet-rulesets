rule TTP_XOR_QUAD_CurrentVersionRun_f70e {
  strings:
    $key_f70e = { a4 61 [2] 80 6f [2] ab 43 [2] 85 61 [2] 91 7a [2] 9e 60 [2] 80 7d [2] 82 7c [2] 99 7a [2] 85 7d [2] 99 52 }

  condition:
    any of them
}