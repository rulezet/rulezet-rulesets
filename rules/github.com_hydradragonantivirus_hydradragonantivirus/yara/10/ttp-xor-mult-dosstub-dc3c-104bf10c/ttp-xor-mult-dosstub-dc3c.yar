rule TTP_XOR_MULT_DOSStub_dc3c {
  strings:
    $key_dc3c = { 88 54 [2] fc 4c [2] bb 4e [2] fc 5f [2] b2 53 [2] be 59 [2] a9 52 [2] b2 1c [2] 8f }

  condition:
    any of them
}