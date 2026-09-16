rule TTP_XOR_MULT_DOSStub_dcea {
  strings:
    $key_dcea = { 88 82 [2] fc 9a [2] bb 98 [2] fc 89 [2] b2 85 [2] be 8f [2] a9 84 [2] b2 ca [2] 8f }

  condition:
    any of them
}