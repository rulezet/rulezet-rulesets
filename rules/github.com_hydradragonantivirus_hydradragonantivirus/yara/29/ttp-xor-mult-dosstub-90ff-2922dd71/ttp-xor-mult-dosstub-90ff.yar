rule TTP_XOR_MULT_DOSStub_90ff {
  strings:
    $key_90ff = { c4 97 [2] b0 8f [2] f7 8d [2] b0 9c [2] fe 90 [2] f2 9a [2] e5 91 [2] fe df [2] c3 }

  condition:
    any of them
}