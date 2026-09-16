rule TTP_XOR_MULT_DOSStub_fadb {
  strings:
    $key_fadb = { ae b3 [2] da ab [2] 9d a9 [2] da b8 [2] 94 b4 [2] 98 be [2] 8f b5 [2] 94 fb [2] a9 }

  condition:
    any of them
}