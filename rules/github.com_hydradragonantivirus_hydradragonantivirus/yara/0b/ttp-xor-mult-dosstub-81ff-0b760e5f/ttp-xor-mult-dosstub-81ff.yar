rule TTP_XOR_MULT_DOSStub_81ff {
  strings:
    $key_81ff = { d5 97 [2] a1 8f [2] e6 8d [2] a1 9c [2] ef 90 [2] e3 9a [2] f4 91 [2] ef df [2] d2 }

  condition:
    any of them
}