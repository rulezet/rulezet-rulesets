rule TTP_XOR_MULT_DOSStub_d5ff {
  strings:
    $key_d5ff = { 81 97 [2] f5 8f [2] b2 8d [2] f5 9c [2] bb 90 [2] b7 9a [2] a0 91 [2] bb df [2] 86 }

  condition:
    any of them
}