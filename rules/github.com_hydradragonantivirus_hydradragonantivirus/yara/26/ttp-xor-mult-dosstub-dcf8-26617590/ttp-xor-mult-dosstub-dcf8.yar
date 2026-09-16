rule TTP_XOR_MULT_DOSStub_dcf8 {
  strings:
    $key_dcf8 = { 88 90 [2] fc 88 [2] bb 8a [2] fc 9b [2] b2 97 [2] be 9d [2] a9 96 [2] b2 d8 [2] 8f }

  condition:
    any of them
}