rule TTP_XOR_MULT_DOSStub_f29d {
  strings:
    $key_f29d = { a6 f5 [2] d2 ed [2] 95 ef [2] d2 fe [2] 9c f2 [2] 90 f8 [2] 87 f3 [2] 9c bd [2] a1 }

  condition:
    any of them
}