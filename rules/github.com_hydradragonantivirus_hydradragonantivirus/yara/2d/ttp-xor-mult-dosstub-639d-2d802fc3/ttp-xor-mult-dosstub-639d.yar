rule TTP_XOR_MULT_DOSStub_639d {
  strings:
    $key_639d = { 37 f5 [2] 43 ed [2] 04 ef [2] 43 fe [2] 0d f2 [2] 01 f8 [2] 16 f3 [2] 0d bd [2] 30 }

  condition:
    any of them
}