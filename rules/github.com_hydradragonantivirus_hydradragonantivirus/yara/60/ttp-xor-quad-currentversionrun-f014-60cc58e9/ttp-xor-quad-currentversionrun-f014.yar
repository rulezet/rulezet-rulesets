rule TTP_XOR_QUAD_CurrentVersionRun_f014 {
  strings:
    $key_f014 = { a3 7b [2] 87 75 [2] ac 59 [2] 82 7b [2] 96 60 [2] 99 7a [2] 87 67 [2] 85 66 [2] 9e 60 [2] 82 67 [2] 9e 48 }

  condition:
    any of them
}