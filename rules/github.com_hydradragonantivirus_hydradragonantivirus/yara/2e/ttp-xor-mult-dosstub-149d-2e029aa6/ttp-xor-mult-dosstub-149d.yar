rule TTP_XOR_MULT_DOSStub_149d {
  strings:
    $key_149d = { 40 f5 [2] 34 ed [2] 73 ef [2] 34 fe [2] 7a f2 [2] 76 f8 [2] 61 f3 [2] 7a bd [2] 47 }

  condition:
    any of them
}