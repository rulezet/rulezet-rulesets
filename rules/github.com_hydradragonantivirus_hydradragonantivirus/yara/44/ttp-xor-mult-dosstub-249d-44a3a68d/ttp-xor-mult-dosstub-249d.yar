rule TTP_XOR_MULT_DOSStub_249d {
  strings:
    $key_249d = { 70 f5 [2] 04 ed [2] 43 ef [2] 04 fe [2] 4a f2 [2] 46 f8 [2] 51 f3 [2] 4a bd [2] 77 }

  condition:
    any of them
}