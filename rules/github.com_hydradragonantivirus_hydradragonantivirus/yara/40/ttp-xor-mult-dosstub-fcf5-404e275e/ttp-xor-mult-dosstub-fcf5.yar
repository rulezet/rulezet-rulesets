rule TTP_XOR_MULT_DOSStub_fcf5 {
  strings:
    $key_fcf5 = { a8 9d [2] dc 85 [2] 9b 87 [2] dc 96 [2] 92 9a [2] 9e 90 [2] 89 9b [2] 92 d5 [2] af }

  condition:
    any of them
}