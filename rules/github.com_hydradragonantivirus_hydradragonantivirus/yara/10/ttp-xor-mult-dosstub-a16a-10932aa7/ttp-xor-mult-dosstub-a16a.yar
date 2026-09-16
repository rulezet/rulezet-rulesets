rule TTP_XOR_MULT_DOSStub_a16a {
  strings:
    $key_a16a = { f5 02 [2] 81 1a [2] c6 18 [2] 81 09 [2] cf 05 [2] c3 0f [2] d4 04 [2] cf 4a [2] f2 }

  condition:
    any of them
}