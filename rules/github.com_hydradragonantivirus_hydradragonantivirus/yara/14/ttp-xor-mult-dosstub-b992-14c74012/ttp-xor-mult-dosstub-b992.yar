rule TTP_XOR_MULT_DOSStub_b992 {
  strings:
    $key_b992 = { ed fa [2] 99 e2 [2] de e0 [2] 99 f1 [2] d7 fd [2] db f7 [2] cc fc [2] d7 b2 [2] ea }

  condition:
    any of them
}