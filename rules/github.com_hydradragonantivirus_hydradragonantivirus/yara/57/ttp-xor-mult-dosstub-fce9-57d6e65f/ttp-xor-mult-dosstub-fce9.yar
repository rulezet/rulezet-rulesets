rule TTP_XOR_MULT_DOSStub_fce9 {
  strings:
    $key_fce9 = { a8 81 [2] dc 99 [2] 9b 9b [2] dc 8a [2] 92 86 [2] 9e 8c [2] 89 87 [2] 92 c9 [2] af }

  condition:
    any of them
}