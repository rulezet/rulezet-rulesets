rule TTP_XOR_MULT_DOSStub_148e {
  strings:
    $key_148e = { 40 e6 [2] 34 fe [2] 73 fc [2] 34 ed [2] 7a e1 [2] 76 eb [2] 61 e0 [2] 7a ae [2] 47 }

  condition:
    any of them
}