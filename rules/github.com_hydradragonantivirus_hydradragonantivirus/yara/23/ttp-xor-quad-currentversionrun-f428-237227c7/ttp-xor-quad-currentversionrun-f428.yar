rule TTP_XOR_QUAD_CurrentVersionRun_f428 {
  strings:
    $key_f428 = { a7 47 [2] 83 49 [2] a8 65 [2] 86 47 [2] 92 5c [2] 9d 46 [2] 83 5b [2] 81 5a [2] 9a 5c [2] 86 5b [2] 9a 74 }

  condition:
    any of them
}