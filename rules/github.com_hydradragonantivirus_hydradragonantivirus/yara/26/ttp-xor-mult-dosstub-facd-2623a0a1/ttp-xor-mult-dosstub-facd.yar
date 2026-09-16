rule TTP_XOR_MULT_DOSStub_facd {
  strings:
    $key_facd = { ae a5 [2] da bd [2] 9d bf [2] da ae [2] 94 a2 [2] 98 a8 [2] 8f a3 [2] 94 ed [2] a9 }

  condition:
    any of them
}