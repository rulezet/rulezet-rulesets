rule TTP_XOR_QUAD_CurrentVersionRun_f729 {
  strings:
    $key_f729 = { a4 46 [2] 80 48 [2] ab 64 [2] 85 46 [2] 91 5d [2] 9e 47 [2] 80 5a [2] 82 5b [2] 99 5d [2] 85 5a [2] 99 75 }

  condition:
    any of them
}