rule TTP_XOR_MULT_DOSStub_a7ff {
  strings:
    $key_a7ff = { f3 97 [2] 87 8f [2] c0 8d [2] 87 9c [2] c9 90 [2] c5 9a [2] d2 91 [2] c9 df [2] f4 }

  condition:
    any of them
}