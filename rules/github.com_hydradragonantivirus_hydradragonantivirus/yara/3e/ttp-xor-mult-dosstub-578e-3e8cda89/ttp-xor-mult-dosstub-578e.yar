rule TTP_XOR_MULT_DOSStub_578e {
  strings:
    $key_578e = { 03 e6 [2] 77 fe [2] 30 fc [2] 77 ed [2] 39 e1 [2] 35 eb [2] 22 e0 [2] 39 ae [2] 04 }

  condition:
    any of them
}