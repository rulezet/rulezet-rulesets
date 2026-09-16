rule TTP_XOR_MULT_DOSStub_c28e {
  strings:
    $key_c28e = { 96 e6 [2] e2 fe [2] a5 fc [2] e2 ed [2] ac e1 [2] a0 eb [2] b7 e0 [2] ac ae [2] 91 }

  condition:
    any of them
}