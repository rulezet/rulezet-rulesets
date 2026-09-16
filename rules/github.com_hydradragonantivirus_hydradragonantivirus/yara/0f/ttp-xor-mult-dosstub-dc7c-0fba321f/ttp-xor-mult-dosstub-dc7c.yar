rule TTP_XOR_MULT_DOSStub_dc7c {
  strings:
    $key_dc7c = { 88 14 [2] fc 0c [2] bb 0e [2] fc 1f [2] b2 13 [2] be 19 [2] a9 12 [2] b2 5c [2] 8f }

  condition:
    any of them
}