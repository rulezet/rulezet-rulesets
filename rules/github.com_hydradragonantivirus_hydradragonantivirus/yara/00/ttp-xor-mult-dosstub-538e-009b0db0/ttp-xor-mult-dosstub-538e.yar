rule TTP_XOR_MULT_DOSStub_538e {
  strings:
    $key_538e = { 07 e6 [2] 73 fe [2] 34 fc [2] 73 ed [2] 3d e1 [2] 31 eb [2] 26 e0 [2] 3d ae [2] 00 }

  condition:
    any of them
}