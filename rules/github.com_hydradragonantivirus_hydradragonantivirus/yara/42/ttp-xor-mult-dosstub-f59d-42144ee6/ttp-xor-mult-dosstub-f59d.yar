rule TTP_XOR_MULT_DOSStub_f59d {
  strings:
    $key_f59d = { a1 f5 [2] d5 ed [2] 92 ef [2] d5 fe [2] 9b f2 [2] 97 f8 [2] 80 f3 [2] 9b bd [2] a6 }

  condition:
    any of them
}