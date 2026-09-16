rule TTP_XOR_MULT_DOSStub_956a {
  strings:
    $key_956a = { c1 02 [2] b5 1a [2] f2 18 [2] b5 09 [2] fb 05 [2] f7 0f [2] e0 04 [2] fb 4a [2] c6 }

  condition:
    any of them
}