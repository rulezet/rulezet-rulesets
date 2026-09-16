rule TTP_XOR_MULT_DOSStub_27df {
  strings:
    $key_27df = { 73 b7 [2] 07 af [2] 40 ad [2] 07 bc [2] 49 b0 [2] 45 ba [2] 52 b1 [2] 49 ff [2] 74 }

  condition:
    any of them
}