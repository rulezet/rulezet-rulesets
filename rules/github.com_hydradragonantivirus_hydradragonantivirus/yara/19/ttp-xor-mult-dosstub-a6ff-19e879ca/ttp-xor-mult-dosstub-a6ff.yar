rule TTP_XOR_MULT_DOSStub_a6ff {
  strings:
    $key_a6ff = { f2 97 [2] 86 8f [2] c1 8d [2] 86 9c [2] c8 90 [2] c4 9a [2] d3 91 [2] c8 df [2] f5 }

  condition:
    any of them
}