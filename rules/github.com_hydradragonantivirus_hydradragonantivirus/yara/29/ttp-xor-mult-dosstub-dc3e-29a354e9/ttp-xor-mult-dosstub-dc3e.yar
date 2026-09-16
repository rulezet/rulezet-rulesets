rule TTP_XOR_MULT_DOSStub_dc3e {
  strings:
    $key_dc3e = { 88 56 [2] fc 4e [2] bb 4c [2] fc 5d [2] b2 51 [2] be 5b [2] a9 50 [2] b2 1e [2] 8f }

  condition:
    any of them
}