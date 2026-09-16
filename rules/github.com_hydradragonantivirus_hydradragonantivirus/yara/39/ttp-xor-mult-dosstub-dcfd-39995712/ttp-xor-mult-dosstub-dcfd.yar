rule TTP_XOR_MULT_DOSStub_dcfd {
  strings:
    $key_dcfd = { 88 95 [2] fc 8d [2] bb 8f [2] fc 9e [2] b2 92 [2] be 98 [2] a9 93 [2] b2 dd [2] 8f }

  condition:
    any of them
}