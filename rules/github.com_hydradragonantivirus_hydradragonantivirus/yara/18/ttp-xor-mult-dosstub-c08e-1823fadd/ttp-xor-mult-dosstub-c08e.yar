rule TTP_XOR_MULT_DOSStub_c08e {
  strings:
    $key_c08e = { 94 e6 [2] e0 fe [2] a7 fc [2] e0 ed [2] ae e1 [2] a2 eb [2] b5 e0 [2] ae ae [2] 93 }

  condition:
    any of them
}