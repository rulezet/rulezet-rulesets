rule TTP_XOR_MULT_DOSStub_fcf9 {
  strings:
    $key_fcf9 = { a8 91 [2] dc 89 [2] 9b 8b [2] dc 9a [2] 92 96 [2] 9e 9c [2] 89 97 [2] 92 d9 [2] af }

  condition:
    any of them
}