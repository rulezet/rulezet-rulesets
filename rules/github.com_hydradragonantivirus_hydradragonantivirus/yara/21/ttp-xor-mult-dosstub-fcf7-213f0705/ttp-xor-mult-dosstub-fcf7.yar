rule TTP_XOR_MULT_DOSStub_fcf7 {
  strings:
    $key_fcf7 = { a8 9f [2] dc 87 [2] 9b 85 [2] dc 94 [2] 92 98 [2] 9e 92 [2] 89 99 [2] 92 d7 [2] af }

  condition:
    any of them
}