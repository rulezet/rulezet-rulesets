rule TTP_XOR_MULT_DOSStub_bf99 {
  strings:
    $key_bf99 = { eb f1 [2] 9f e9 [2] d8 eb [2] 9f fa [2] d1 f6 [2] dd fc [2] ca f7 [2] d1 b9 [2] ec }

  condition:
    any of them
}