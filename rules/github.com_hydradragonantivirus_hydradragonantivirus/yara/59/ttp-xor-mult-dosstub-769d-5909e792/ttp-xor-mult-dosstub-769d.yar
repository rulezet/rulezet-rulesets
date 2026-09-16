rule TTP_XOR_MULT_DOSStub_769d {
  strings:
    $key_769d = { 22 f5 [2] 56 ed [2] 11 ef [2] 56 fe [2] 18 f2 [2] 14 f8 [2] 03 f3 [2] 18 bd [2] 25 }

  condition:
    any of them
}