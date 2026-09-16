rule TTP_XOR_MULT_DOSStub_bbc5 {
  strings:
    $key_bbc5 = { ef ad [2] 9b b5 [2] dc b7 [2] 9b a6 [2] d5 aa [2] d9 a0 [2] ce ab [2] d5 e5 [2] e8 }

  condition:
    any of them
}