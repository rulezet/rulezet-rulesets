rule TTP_XOR_MULT_DOSStub_dcb8 {
  strings:
    $key_dcb8 = { 88 d0 [2] fc c8 [2] bb ca [2] fc db [2] b2 d7 [2] be dd [2] a9 d6 [2] b2 98 [2] 8f }

  condition:
    any of them
}