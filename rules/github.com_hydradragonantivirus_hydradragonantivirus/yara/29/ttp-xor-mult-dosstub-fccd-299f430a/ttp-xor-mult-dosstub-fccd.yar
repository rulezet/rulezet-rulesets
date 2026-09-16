rule TTP_XOR_MULT_DOSStub_fccd {
  strings:
    $key_fccd = { a8 a5 [2] dc bd [2] 9b bf [2] dc ae [2] 92 a2 [2] 9e a8 [2] 89 a3 [2] 92 ed [2] af }

  condition:
    any of them
}