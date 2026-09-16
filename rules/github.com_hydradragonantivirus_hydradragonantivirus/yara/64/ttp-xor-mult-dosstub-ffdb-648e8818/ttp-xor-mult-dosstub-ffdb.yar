rule TTP_XOR_MULT_DOSStub_ffdb {
  strings:
    $key_ffdb = { ab b3 [2] df ab [2] 98 a9 [2] df b8 [2] 91 b4 [2] 9d be [2] 8a b5 [2] 91 fb [2] ac }

  condition:
    any of them
}