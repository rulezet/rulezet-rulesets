rule TTP_XOR_QUAD_CurrentVersionRun_f438 {
  strings:
    $key_f438 = { a7 57 [2] 83 59 [2] a8 75 [2] 86 57 [2] 92 4c [2] 9d 56 [2] 83 4b [2] 81 4a [2] 9a 4c [2] 86 4b [2] 9a 64 }

  condition:
    any of them
}