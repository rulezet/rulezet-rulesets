rule TTP_XOR_MULT_DOSStub_018e {
  strings:
    $key_018e = { 55 e6 [2] 21 fe [2] 66 fc [2] 21 ed [2] 6f e1 [2] 63 eb [2] 74 e0 [2] 6f ae [2] 52 }

  condition:
    any of them
}