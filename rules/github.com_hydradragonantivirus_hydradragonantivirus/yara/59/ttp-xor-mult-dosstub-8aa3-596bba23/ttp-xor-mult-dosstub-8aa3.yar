rule TTP_XOR_MULT_DOSStub_8aa3 {
  strings:
    $key_8aa3 = { de cb [2] aa d3 [2] ed d1 [2] aa c0 [2] e4 cc [2] e8 c6 [2] ff cd [2] e4 83 [2] d9 }

  condition:
    any of them
}