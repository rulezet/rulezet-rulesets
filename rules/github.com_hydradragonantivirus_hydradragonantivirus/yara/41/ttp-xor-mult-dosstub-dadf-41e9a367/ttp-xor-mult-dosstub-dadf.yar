rule TTP_XOR_MULT_DOSStub_dadf {
  strings:
    $key_dadf = { 8e b7 [2] fa af [2] bd ad [2] fa bc [2] b4 b0 [2] b8 ba [2] af b1 [2] b4 ff [2] 89 }

  condition:
    any of them
}