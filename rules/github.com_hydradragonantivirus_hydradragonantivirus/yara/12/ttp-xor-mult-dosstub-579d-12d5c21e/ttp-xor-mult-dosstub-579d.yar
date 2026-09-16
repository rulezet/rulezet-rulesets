rule TTP_XOR_MULT_DOSStub_579d {
  strings:
    $key_579d = { 03 f5 [2] 77 ed [2] 30 ef [2] 77 fe [2] 39 f2 [2] 35 f8 [2] 22 f3 [2] 39 bd [2] 04 }

  condition:
    any of them
}