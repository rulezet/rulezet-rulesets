rule TTP_XOR_MULT_DOSStub_d56a {
  strings:
    $key_d56a = { 81 02 [2] f5 1a [2] b2 18 [2] f5 09 [2] bb 05 [2] b7 0f [2] a0 04 [2] bb 4a [2] 86 }

  condition:
    any of them
}