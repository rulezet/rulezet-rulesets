rule TTP_XOR_MULT_DOSStub_cddb {
  strings:
    $key_cddb = { 99 b3 [2] ed ab [2] aa a9 [2] ed b8 [2] a3 b4 [2] af be [2] b8 b5 [2] a3 fb [2] 9e }

  condition:
    any of them
}