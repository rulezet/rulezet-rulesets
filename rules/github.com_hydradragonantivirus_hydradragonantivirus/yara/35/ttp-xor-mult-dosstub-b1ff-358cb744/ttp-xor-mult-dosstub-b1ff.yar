rule TTP_XOR_MULT_DOSStub_b1ff {
  strings:
    $key_b1ff = { e5 97 [2] 91 8f [2] d6 8d [2] 91 9c [2] df 90 [2] d3 9a [2] c4 91 [2] df df [2] e2 }

  condition:
    any of them
}