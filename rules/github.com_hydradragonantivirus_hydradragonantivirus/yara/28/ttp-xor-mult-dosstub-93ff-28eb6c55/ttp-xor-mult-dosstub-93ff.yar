rule TTP_XOR_MULT_DOSStub_93ff {
  strings:
    $key_93ff = { c7 97 [2] b3 8f [2] f4 8d [2] b3 9c [2] fd 90 [2] f1 9a [2] e6 91 [2] fd df [2] c0 }

  condition:
    any of them
}