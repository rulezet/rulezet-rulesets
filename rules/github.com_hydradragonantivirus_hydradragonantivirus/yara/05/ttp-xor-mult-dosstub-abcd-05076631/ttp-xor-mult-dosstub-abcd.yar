rule TTP_XOR_MULT_DOSStub_abcd {
  strings:
    $key_abcd = { ff a5 [2] 8b bd [2] cc bf [2] 8b ae [2] c5 a2 [2] c9 a8 [2] de a3 [2] c5 ed [2] f8 }

  condition:
    any of them
}