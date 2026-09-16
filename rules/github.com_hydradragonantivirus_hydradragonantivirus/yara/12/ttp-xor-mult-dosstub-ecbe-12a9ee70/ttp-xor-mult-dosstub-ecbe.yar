rule TTP_XOR_MULT_DOSStub_ecbe {
  strings:
    $key_ecbe = { b8 d6 [2] cc ce [2] 8b cc [2] cc dd [2] 82 d1 [2] 8e db [2] 99 d0 [2] 82 9e [2] bf }

  condition:
    any of them
}