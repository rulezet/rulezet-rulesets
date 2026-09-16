rule TTP_XOR_MULT_DOSStub_fc04 {
  strings:
    $key_fc04 = { a8 6c [2] dc 74 [2] 9b 76 [2] dc 67 [2] 92 6b [2] 9e 61 [2] 89 6a [2] 92 24 [2] af }

  condition:
    any of them
}