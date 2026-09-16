rule TTP_XOR_MULT_DOSStub_06df {
  strings:
    $key_06df = { 52 b7 [2] 26 af [2] 61 ad [2] 26 bc [2] 68 b0 [2] 64 ba [2] 73 b1 [2] 68 ff [2] 55 }

  condition:
    any of them
}