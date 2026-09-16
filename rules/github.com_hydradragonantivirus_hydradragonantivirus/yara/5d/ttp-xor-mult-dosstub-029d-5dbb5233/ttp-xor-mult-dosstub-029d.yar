rule TTP_XOR_MULT_DOSStub_029d {
  strings:
    $key_029d = { 56 f5 [2] 22 ed [2] 65 ef [2] 22 fe [2] 6c f2 [2] 60 f8 [2] 77 f3 [2] 6c bd [2] 51 }

  condition:
    any of them
}