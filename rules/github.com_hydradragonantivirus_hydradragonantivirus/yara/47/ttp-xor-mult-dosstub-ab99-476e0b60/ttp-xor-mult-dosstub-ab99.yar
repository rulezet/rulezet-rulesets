rule TTP_XOR_MULT_DOSStub_ab99 {
  strings:
    $key_ab99 = { ff f1 [2] 8b e9 [2] cc eb [2] 8b fa [2] c5 f6 [2] c9 fc [2] de f7 [2] c5 b9 [2] f8 }

  condition:
    any of them
}