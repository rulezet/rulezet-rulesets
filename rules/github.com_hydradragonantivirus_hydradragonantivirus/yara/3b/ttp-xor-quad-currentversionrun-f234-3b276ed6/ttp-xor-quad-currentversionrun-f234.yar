rule TTP_XOR_QUAD_CurrentVersionRun_f234 {
  strings:
    $key_f234 = { a1 5b [2] 85 55 [2] ae 79 [2] 80 5b [2] 94 40 [2] 9b 5a [2] 85 47 [2] 87 46 [2] 9c 40 [2] 80 47 [2] 9c 68 }

  condition:
    any of them
}