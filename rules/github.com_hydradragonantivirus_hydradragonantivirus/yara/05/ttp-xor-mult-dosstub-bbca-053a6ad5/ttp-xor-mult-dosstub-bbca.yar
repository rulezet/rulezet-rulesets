rule TTP_XOR_MULT_DOSStub_bbca {
  strings:
    $key_bbca = { ef a2 [2] 9b ba [2] dc b8 [2] 9b a9 [2] d5 a5 [2] d9 af [2] ce a4 [2] d5 ea [2] e8 }

  condition:
    any of them
}