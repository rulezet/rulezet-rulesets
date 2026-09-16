rule TTP_XOR_MULT_DOSStub_f1df {
  strings:
    $key_f1df = { a5 b7 [2] d1 af [2] 96 ad [2] d1 bc [2] 9f b0 [2] 93 ba [2] 84 b1 [2] 9f ff [2] a2 }

  condition:
    any of them
}