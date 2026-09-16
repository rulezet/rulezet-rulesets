rule TTP_XOR_MULT_DOSStub_ec99 {
  strings:
    $key_ec99 = { b8 f1 [2] cc e9 [2] 8b eb [2] cc fa [2] 82 f6 [2] 8e fc [2] 99 f7 [2] 82 b9 [2] bf }

  condition:
    any of them
}