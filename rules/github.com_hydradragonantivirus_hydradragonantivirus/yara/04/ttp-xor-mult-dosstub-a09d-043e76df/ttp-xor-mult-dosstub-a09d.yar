rule TTP_XOR_MULT_DOSStub_a09d {
  strings:
    $key_a09d = { f4 f5 [2] 80 ed [2] c7 ef [2] 80 fe [2] ce f2 [2] c2 f8 [2] d5 f3 [2] ce bd [2] f3 }

  condition:
    any of them
}