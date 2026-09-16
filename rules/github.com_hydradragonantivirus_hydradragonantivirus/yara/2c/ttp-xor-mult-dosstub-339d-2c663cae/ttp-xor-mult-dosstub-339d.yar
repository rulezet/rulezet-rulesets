rule TTP_XOR_MULT_DOSStub_339d {
  strings:
    $key_339d = { 67 f5 [2] 13 ed [2] 54 ef [2] 13 fe [2] 5d f2 [2] 51 f8 [2] 46 f3 [2] 5d bd [2] 60 }

  condition:
    any of them
}