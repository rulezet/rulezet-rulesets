rule TTP_XOR_MULT_DOSStub_e48e {
  strings:
    $key_e48e = { b0 e6 [2] c4 fe [2] 83 fc [2] c4 ed [2] 8a e1 [2] 86 eb [2] 91 e0 [2] 8a ae [2] b7 }

  condition:
    any of them
}