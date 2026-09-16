rule TTP_XOR_QUAD_CurrentVersionRun_f214 {
  strings:
    $key_f214 = { a1 7b [2] 85 75 [2] ae 59 [2] 80 7b [2] 94 60 [2] 9b 7a [2] 85 67 [2] 87 66 [2] 9c 60 [2] 80 67 [2] 9c 48 }

  condition:
    any of them
}