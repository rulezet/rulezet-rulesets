rule TTP_XOR_MULT_DOSStub_876a {
  strings:
    $key_876a = { d3 02 [2] a7 1a [2] e0 18 [2] a7 09 [2] e9 05 [2] e5 0f [2] f2 04 [2] e9 4a [2] d4 }

  condition:
    any of them
}