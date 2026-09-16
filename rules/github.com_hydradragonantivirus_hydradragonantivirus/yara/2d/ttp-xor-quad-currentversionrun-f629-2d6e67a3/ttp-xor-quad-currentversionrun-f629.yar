rule TTP_XOR_QUAD_CurrentVersionRun_f629 {
  strings:
    $key_f629 = { a5 46 [2] 81 48 [2] aa 64 [2] 84 46 [2] 90 5d [2] 9f 47 [2] 81 5a [2] 83 5b [2] 98 5d [2] 84 5a [2] 98 75 }

  condition:
    any of them
}