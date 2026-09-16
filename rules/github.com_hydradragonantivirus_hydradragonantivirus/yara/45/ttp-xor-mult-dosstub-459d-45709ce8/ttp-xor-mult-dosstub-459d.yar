rule TTP_XOR_MULT_DOSStub_459d {
  strings:
    $key_459d = { 11 f5 [2] 65 ed [2] 22 ef [2] 65 fe [2] 2b f2 [2] 27 f8 [2] 30 f3 [2] 2b bd [2] 16 }

  condition:
    any of them
}