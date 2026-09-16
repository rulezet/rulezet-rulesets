rule TTP_XOR_MULT_DOSStub_dc5c {
  strings:
    $key_dc5c = { 88 34 [2] fc 2c [2] bb 2e [2] fc 3f [2] b2 33 [2] be 39 [2] a9 32 [2] b2 7c [2] 8f }

  condition:
    any of them
}