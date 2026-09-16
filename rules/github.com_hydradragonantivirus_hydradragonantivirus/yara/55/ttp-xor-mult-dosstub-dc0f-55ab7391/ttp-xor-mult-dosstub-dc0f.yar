rule TTP_XOR_MULT_DOSStub_dc0f {
  strings:
    $key_dc0f = { 88 67 [2] fc 7f [2] bb 7d [2] fc 6c [2] b2 60 [2] be 6a [2] a9 61 [2] b2 2f [2] 8f }

  condition:
    any of them
}