rule TTP_XOR_MULT_DOSStub_da99 {
  strings:
    $key_da99 = { 8e f1 [2] fa e9 [2] bd eb [2] fa fa [2] b4 f6 [2] b8 fc [2] af f7 [2] b4 b9 [2] 89 }

  condition:
    any of them
}