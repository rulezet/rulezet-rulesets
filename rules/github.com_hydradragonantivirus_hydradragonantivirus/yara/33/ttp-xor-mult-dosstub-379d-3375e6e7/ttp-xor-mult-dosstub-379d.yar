rule TTP_XOR_MULT_DOSStub_379d {
  strings:
    $key_379d = { 63 f5 [2] 17 ed [2] 50 ef [2] 17 fe [2] 59 f2 [2] 55 f8 [2] 42 f3 [2] 59 bd [2] 64 }

  condition:
    any of them
}