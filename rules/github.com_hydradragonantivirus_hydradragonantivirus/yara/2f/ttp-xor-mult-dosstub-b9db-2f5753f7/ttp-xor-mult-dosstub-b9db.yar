rule TTP_XOR_MULT_DOSStub_b9db {
  strings:
    $key_b9db = { ed b3 [2] 99 ab [2] de a9 [2] 99 b8 [2] d7 b4 [2] db be [2] cc b5 [2] d7 fb [2] ea }

  condition:
    any of them
}