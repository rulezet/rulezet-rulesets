rule TTP_XOR_MULT_DOSStub_dfdb {
  strings:
    $key_dfdb = { 8b b3 [2] ff ab [2] b8 a9 [2] ff b8 [2] b1 b4 [2] bd be [2] aa b5 [2] b1 fb [2] 8c }

  condition:
    any of them
}