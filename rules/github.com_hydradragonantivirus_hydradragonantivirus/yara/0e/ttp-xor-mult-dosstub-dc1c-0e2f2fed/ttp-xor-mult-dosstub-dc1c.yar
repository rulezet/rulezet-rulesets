rule TTP_XOR_MULT_DOSStub_dc1c {
  strings:
    $key_dc1c = { 88 74 [2] fc 6c [2] bb 6e [2] fc 7f [2] b2 73 [2] be 79 [2] a9 72 [2] b2 3c [2] 8f }

  condition:
    any of them
}