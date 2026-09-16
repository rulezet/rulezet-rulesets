rule TTP_XOR_MULT_DOSStub_009d {
  strings:
    $key_009d = { 54 f5 [2] 20 ed [2] 67 ef [2] 20 fe [2] 6e f2 [2] 62 f8 [2] 75 f3 [2] 6e bd [2] 53 }

  condition:
    any of them
}