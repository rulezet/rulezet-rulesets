rule TTP_XOR_MULT_DOSStub_d78e {
  strings:
    $key_d78e = { 83 e6 [2] f7 fe [2] b0 fc [2] f7 ed [2] b9 e1 [2] b5 eb [2] a2 e0 [2] b9 ae [2] 84 }

  condition:
    any of them
}