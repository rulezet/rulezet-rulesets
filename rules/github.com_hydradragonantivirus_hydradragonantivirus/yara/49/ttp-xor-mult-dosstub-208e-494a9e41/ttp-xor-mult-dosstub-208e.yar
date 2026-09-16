rule TTP_XOR_MULT_DOSStub_208e {
  strings:
    $key_208e = { 74 e6 [2] 00 fe [2] 47 fc [2] 00 ed [2] 4e e1 [2] 42 eb [2] 55 e0 [2] 4e ae [2] 73 }

  condition:
    any of them
}