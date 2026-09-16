rule TTP_XOR_MULT_DOSStub_bfdb {
  strings:
    $key_bfdb = { eb b3 [2] 9f ab [2] d8 a9 [2] 9f b8 [2] d1 b4 [2] dd be [2] ca b5 [2] d1 fb [2] ec }

  condition:
    any of them
}