rule TTP_XOR_MULT_DOSStub_fcf4 {
  strings:
    $key_fcf4 = { a8 9c [2] dc 84 [2] 9b 86 [2] dc 97 [2] 92 9b [2] 9e 91 [2] 89 9a [2] 92 d4 [2] af }

  condition:
    any of them
}