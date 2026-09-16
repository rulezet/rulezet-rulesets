rule TTP_XOR_MULT_DOSStub_fc9f {
  strings:
    $key_fc9f = { a8 f7 [2] dc ef [2] 9b ed [2] dc fc [2] 92 f0 [2] 9e fa [2] 89 f1 [2] 92 bf [2] af }

  condition:
    any of them
}