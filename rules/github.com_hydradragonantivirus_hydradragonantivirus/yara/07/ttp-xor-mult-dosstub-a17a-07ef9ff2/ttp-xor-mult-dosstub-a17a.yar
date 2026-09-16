rule TTP_XOR_MULT_DOSStub_a17a {
  strings:
    $key_a17a = { f5 12 [2] 81 0a [2] c6 08 [2] 81 19 [2] cf 15 [2] c3 1f [2] d4 14 [2] cf 5a [2] f2 }

  condition:
    any of them
}