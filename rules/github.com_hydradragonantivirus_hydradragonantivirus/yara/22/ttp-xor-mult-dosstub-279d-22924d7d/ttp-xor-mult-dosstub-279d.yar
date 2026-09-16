rule TTP_XOR_MULT_DOSStub_279d {
  strings:
    $key_279d = { 73 f5 [2] 07 ed [2] 40 ef [2] 07 fe [2] 49 f2 [2] 45 f8 [2] 52 f3 [2] 49 bd [2] 74 }

  condition:
    any of them
}