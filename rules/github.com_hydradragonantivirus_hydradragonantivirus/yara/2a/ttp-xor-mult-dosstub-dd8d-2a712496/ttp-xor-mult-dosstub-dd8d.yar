rule TTP_XOR_MULT_DOSStub_dd8d {
  strings:
    $key_dd8d = { 89 e5 [2] fd fd [2] ba ff [2] fd ee [2] b3 e2 [2] bf e8 [2] a8 e3 [2] b3 ad [2] 8e }

  condition:
    any of them
}