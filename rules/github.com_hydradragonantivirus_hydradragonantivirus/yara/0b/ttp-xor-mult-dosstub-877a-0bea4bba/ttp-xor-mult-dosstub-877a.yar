rule TTP_XOR_MULT_DOSStub_877a {
  strings:
    $key_877a = { d3 12 [2] a7 0a [2] e0 08 [2] a7 19 [2] e9 15 [2] e5 1f [2] f2 14 [2] e9 5a [2] d4 }

  condition:
    any of them
}