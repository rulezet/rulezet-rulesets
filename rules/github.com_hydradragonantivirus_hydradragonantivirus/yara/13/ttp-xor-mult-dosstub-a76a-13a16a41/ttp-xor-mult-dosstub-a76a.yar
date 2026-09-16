rule TTP_XOR_MULT_DOSStub_a76a {
  strings:
    $key_a76a = { f3 02 [2] 87 1a [2] c0 18 [2] 87 09 [2] c9 05 [2] c5 0f [2] d2 04 [2] c9 4a [2] f4 }

  condition:
    any of them
}