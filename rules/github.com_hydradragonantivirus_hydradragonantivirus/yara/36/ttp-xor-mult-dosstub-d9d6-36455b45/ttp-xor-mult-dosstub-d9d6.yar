rule TTP_XOR_MULT_DOSStub_d9d6 {
  strings:
    $key_d9d6 = { 8d be [2] f9 a6 [2] be a4 [2] f9 b5 [2] b7 b9 [2] bb b3 [2] ac b8 [2] b7 f6 [2] 8a }

  condition:
    any of them
}