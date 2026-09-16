rule TTP_XOR_MULT_DOSStub_e18e {
  strings:
    $key_e18e = { b5 e6 [2] c1 fe [2] 86 fc [2] c1 ed [2] 8f e1 [2] 83 eb [2] 94 e0 [2] 8f ae [2] b2 }

  condition:
    any of them
}