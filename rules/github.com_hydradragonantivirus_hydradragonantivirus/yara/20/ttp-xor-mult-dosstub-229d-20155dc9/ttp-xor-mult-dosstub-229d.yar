rule TTP_XOR_MULT_DOSStub_229d {
  strings:
    $key_229d = { 76 f5 [2] 02 ed [2] 45 ef [2] 02 fe [2] 4c f2 [2] 40 f8 [2] 57 f3 [2] 4c bd [2] 71 }

  condition:
    any of them
}