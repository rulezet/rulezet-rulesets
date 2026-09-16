rule TTP_XOR_MULT_DOSStub_fcf2 {
  strings:
    $key_fcf2 = { a8 9a [2] dc 82 [2] 9b 80 [2] dc 91 [2] 92 9d [2] 9e 97 [2] 89 9c [2] 92 d2 [2] af }

  condition:
    any of them
}