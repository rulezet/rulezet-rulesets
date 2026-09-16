rule TTP_XOR_MULT_DOSStub_129d {
  strings:
    $key_129d = { 46 f5 [2] 32 ed [2] 75 ef [2] 32 fe [2] 7c f2 [2] 70 f8 [2] 67 f3 [2] 7c bd [2] 41 }

  condition:
    any of them
}