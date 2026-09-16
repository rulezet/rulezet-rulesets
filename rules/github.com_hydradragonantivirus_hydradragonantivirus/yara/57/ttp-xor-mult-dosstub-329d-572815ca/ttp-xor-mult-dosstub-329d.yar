rule TTP_XOR_MULT_DOSStub_329d {
  strings:
    $key_329d = { 66 f5 [2] 12 ed [2] 55 ef [2] 12 fe [2] 5c f2 [2] 50 f8 [2] 47 f3 [2] 5c bd [2] 61 }

  condition:
    any of them
}