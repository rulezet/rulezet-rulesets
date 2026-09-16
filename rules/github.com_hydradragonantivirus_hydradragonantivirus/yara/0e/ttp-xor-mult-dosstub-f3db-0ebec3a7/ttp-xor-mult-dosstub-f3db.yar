rule TTP_XOR_MULT_DOSStub_f3db {
  strings:
    $key_f3db = { a7 b3 [2] d3 ab [2] 94 a9 [2] d3 b8 [2] 9d b4 [2] 91 be [2] 86 b5 [2] 9d fb [2] a0 }

  condition:
    any of them
}