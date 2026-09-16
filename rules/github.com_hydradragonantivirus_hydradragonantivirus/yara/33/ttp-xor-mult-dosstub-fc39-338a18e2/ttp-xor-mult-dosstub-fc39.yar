rule TTP_XOR_MULT_DOSStub_fc39 {
  strings:
    $key_fc39 = { a8 51 [2] dc 49 [2] 9b 4b [2] dc 5a [2] 92 56 [2] 9e 5c [2] 89 57 [2] 92 19 [2] af }

  condition:
    any of them
}