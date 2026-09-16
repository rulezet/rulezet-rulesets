rule TTP_XOR_MULT_DOSStub_fbdb {
  strings:
    $key_fbdb = { af b3 [2] db ab [2] 9c a9 [2] db b8 [2] 95 b4 [2] 99 be [2] 8e b5 [2] 95 fb [2] a8 }

  condition:
    any of them
}