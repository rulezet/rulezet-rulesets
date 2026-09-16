rule TTP_XOR_QUAD_CurrentVersionRun_f4e7 {
  strings:
    $key_f4e7 = { a7 88 [2] 83 86 [2] a8 aa [2] 86 88 [2] 92 93 [2] 9d 89 [2] 83 94 [2] 81 95 [2] 9a 93 [2] 86 94 [2] 9a bb }

  condition:
    any of them
}