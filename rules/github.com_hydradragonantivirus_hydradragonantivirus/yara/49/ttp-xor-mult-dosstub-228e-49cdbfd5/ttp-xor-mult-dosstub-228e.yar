rule TTP_XOR_MULT_DOSStub_228e {
  strings:
    $key_228e = { 76 e6 [2] 02 fe [2] 45 fc [2] 02 ed [2] 4c e1 [2] 40 eb [2] 57 e0 [2] 4c ae [2] 71 }

  condition:
    any of them
}