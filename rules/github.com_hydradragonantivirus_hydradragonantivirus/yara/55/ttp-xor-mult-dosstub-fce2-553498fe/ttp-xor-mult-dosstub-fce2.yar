rule TTP_XOR_MULT_DOSStub_fce2 {
  strings:
    $key_fce2 = { a8 8a [2] dc 92 [2] 9b 90 [2] dc 81 [2] 92 8d [2] 9e 87 [2] 89 8c [2] 92 c2 [2] af }

  condition:
    any of them
}