rule TTP_XOR_MULT_DOSStub_f7df {
  strings:
    $key_f7df = { a3 b7 [2] d7 af [2] 90 ad [2] d7 bc [2] 99 b0 [2] 95 ba [2] 82 b1 [2] 99 ff [2] a4 }

  condition:
    any of them
}