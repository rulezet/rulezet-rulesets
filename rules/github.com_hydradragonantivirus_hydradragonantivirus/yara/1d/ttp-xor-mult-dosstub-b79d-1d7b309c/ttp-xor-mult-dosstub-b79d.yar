rule TTP_XOR_MULT_DOSStub_b79d {
  strings:
    $key_b79d = { e3 f5 [2] 97 ed [2] d0 ef [2] 97 fe [2] d9 f2 [2] d5 f8 [2] c2 f3 [2] d9 bd [2] e4 }

  condition:
    any of them
}