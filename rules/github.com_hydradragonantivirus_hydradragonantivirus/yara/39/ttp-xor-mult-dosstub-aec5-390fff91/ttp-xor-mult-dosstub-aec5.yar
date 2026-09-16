rule TTP_XOR_MULT_DOSStub_aec5 {
  strings:
    $key_aec5 = { fa ad [2] 8e b5 [2] c9 b7 [2] 8e a6 [2] c0 aa [2] cc a0 [2] db ab [2] c0 e5 [2] fd }

  condition:
    any of them
}