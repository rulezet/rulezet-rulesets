rule TTP_XOR_MULT_DOSStub_a06a {
  strings:
    $key_a06a = { f4 02 [2] 80 1a [2] c7 18 [2] 80 09 [2] ce 05 [2] c2 0f [2] d5 04 [2] ce 4a [2] f3 }

  condition:
    any of them
}