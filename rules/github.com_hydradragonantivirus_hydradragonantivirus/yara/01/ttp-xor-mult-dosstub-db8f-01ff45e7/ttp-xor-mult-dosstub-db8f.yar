rule TTP_XOR_MULT_DOSStub_db8f {
  strings:
    $key_db8f = { 8f e7 [2] fb ff [2] bc fd [2] fb ec [2] b5 e0 [2] b9 ea [2] ae e1 [2] b5 af [2] 88 }

  condition:
    any of them
}