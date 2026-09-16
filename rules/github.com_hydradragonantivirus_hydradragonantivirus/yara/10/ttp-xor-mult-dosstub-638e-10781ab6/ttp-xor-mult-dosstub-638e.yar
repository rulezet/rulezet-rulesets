rule TTP_XOR_MULT_DOSStub_638e {
  strings:
    $key_638e = { 37 e6 [2] 43 fe [2] 04 fc [2] 43 ed [2] 0d e1 [2] 01 eb [2] 16 e0 [2] 0d ae [2] 30 }

  condition:
    any of them
}