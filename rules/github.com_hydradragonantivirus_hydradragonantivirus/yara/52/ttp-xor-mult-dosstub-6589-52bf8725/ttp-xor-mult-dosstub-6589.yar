rule TTP_XOR_MULT_DOSStub_6589 {
  strings:
    $key_6589 = { 31 e1 [2] 45 f9 [2] 02 fb [2] 45 ea [2] 0b e6 [2] 07 ec [2] 10 e7 [2] 0b a9 [2] 36 }

  condition:
    any of them
}