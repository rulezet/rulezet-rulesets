rule TTP_XOR_MULT_DOSStub_759d {
  strings:
    $key_759d = { 21 f5 [2] 55 ed [2] 12 ef [2] 55 fe [2] 1b f2 [2] 17 f8 [2] 00 f3 [2] 1b bd [2] 26 }

  condition:
    any of them
}