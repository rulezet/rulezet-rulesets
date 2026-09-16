rule TTP_XOR_QUAD_CurrentVersionRun_f714 {
  strings:
    $key_f714 = { a4 7b [2] 80 75 [2] ab 59 [2] 85 7b [2] 91 60 [2] 9e 7a [2] 80 67 [2] 82 66 [2] 99 60 [2] 85 67 [2] 99 48 }

  condition:
    any of them
}