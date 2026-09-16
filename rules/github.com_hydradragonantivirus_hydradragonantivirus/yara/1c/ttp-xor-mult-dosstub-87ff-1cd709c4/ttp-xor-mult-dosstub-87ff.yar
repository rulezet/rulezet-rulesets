rule TTP_XOR_MULT_DOSStub_87ff {
  strings:
    $key_87ff = { d3 97 [2] a7 8f [2] e0 8d [2] a7 9c [2] e9 90 [2] e5 9a [2] f2 91 [2] e9 df [2] d4 }

  condition:
    any of them
}